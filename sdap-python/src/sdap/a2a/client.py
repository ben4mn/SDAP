"""High-level SDAP client for A2A session management."""

from __future__ import annotations

import json
import time
from typing import Callable

import httpx

from sdap.a2a.middleware import unwrap_a2a_message, wrap_a2a_message
from sdap.handshake.protocol import (
    Session,
    create_handshake_confirm,
    create_handshake_init,
    process_handshake_confirm,
)
from sdap.handshake.session_store import SessionStore
from sdap.identity.did import DIDDocument
from sdap.identity.keys import KeyPair, generate_x25519_keypair


class SDAPClient:
    """High-level SDAP client for establishing and using secure sessions.

    Example::

        client = SDAPClient(
            did="did:sdap:acme.com:agent",
            auth_keypair=my_ed25519_keypair,
            session_store=SessionStore(),
        )
        session = await client.establish_session(
            target_did="did:sdap:partner.com:agent",
            requested_scopes=["records:read"],
            resolve_did_func=my_resolver,
            http_client=httpx_client,
        )
        envelope = client.send_secure(session, {"action": "get-record"})
    """

    def __init__(
        self,
        did: str,
        auth_keypair: KeyPair,
        session_store: SessionStore,
    ) -> None:
        self.did = did
        self.auth_keypair = auth_keypair
        self.session_store = session_store

    async def establish_session(
        self,
        target_did: str,
        requested_scopes: list[str],
        resolve_did_func: Callable[[str], DIDDocument],
        http_client: httpx.AsyncClient,
    ) -> Session:
        """Perform the full 3-message SDAP handshake with a target agent.

        This method:
        1. Resolves the target DID to find the handshake endpoint.
        2. Sends INIT message via HTTP POST to the target's handshake endpoint.
        3. Receives the ACCEPT message.
        4. Sends the CONFIRM message.
        5. Stores and returns the established session.

        Args:
            target_did: DID of the target agent.
            requested_scopes: Scopes to request.
            resolve_did_func: Callable(did: str) -> DIDDocument
            http_client: httpx async HTTP client.

        Returns:
            The established :class:`Session`.
        """
        # Resolve target to get handshake endpoint
        target_doc = resolve_did_func(target_did)
        handshake_endpoint = _find_handshake_endpoint(target_doc)

        if not handshake_endpoint:
            raise ValueError(
                f"Target DID {target_did!r} does not advertise a handshake endpoint"
            )

        # Step 1: Create INIT
        ephemeral = generate_x25519_keypair("ephemeral")
        init_msg, ephemeral_private = create_handshake_init(
            initiator_did=self.did,
            target_did=target_did,
            auth_private_key=self.auth_keypair.private_key,
            auth_key_id=self.auth_keypair.key_id,
            ephemeral_keypair=ephemeral,
            requested_scopes=requested_scopes,
        )

        # Extract our nonce from the init payload for later verification
        import base64 as _b64
        jws = init_msg["jws"]
        parts = jws.split(".")
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        init_payload = json.loads(_b64.urlsafe_b64decode(payload_b64))
        initiator_nonce = init_payload["nonce"]

        # Step 2: Send INIT, receive ACCEPT
        response = await http_client.post(
            handshake_endpoint,
            json=init_msg,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code not in (200, 201):
            raise ValueError(
                f"Handshake INIT rejected: HTTP {response.status_code}"
            )
        accept_msg = response.json()

        # Step 3: Process ACCEPT and create CONFIRM
        confirm_msg, session = create_handshake_confirm(
            accept_msg=accept_msg,
            initiator_did=self.did,
            initiator_nonce=initiator_nonce,
            auth_private_key=self.auth_keypair.private_key,
            auth_key_id=self.auth_keypair.key_id,
            initiator_ephemeral_private=ephemeral_private,
        )

        # Step 4: Send CONFIRM
        confirm_url = f"{handshake_endpoint}/confirm"
        response = await http_client.post(
            confirm_url,
            json=confirm_msg,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code not in (200, 201, 204):
            raise ValueError(
                f"Handshake CONFIRM rejected: HTTP {response.status_code}"
            )

        # Store session
        self.session_store.store(session)
        return session

    def send_secure(
        self,
        session: Session,
        payload: dict,
        data_classification: str = "internal",
    ) -> dict:
        """Create an encrypted SDAP envelope for an A2A message.

        Args:
            session: The active session.
            payload: A2A message payload dict.
            data_classification: Data sensitivity label (e.g. ``"internal"``, ``"confidential"``).

        Returns:
            Wrapped message dict suitable for sending over the wire.
        """
        message = {
            "payload": payload,
            "dataClassification": data_classification,
            "timestamp": int(time.time()),
        }
        return wrap_a2a_message(
            message=message,
            session=session,
            encrypt_key=session.encrypt_key,
            sender_did=self.did,
        )

    def receive_secure(
        self,
        envelope: dict,
        session: Session,
    ) -> dict:
        """Decrypt an SDAP envelope and return the inner A2A message.

        Args:
            envelope: Wrapped message dict from the wire.
            session: The active session.

        Returns:
            The decrypted A2A message dict.
        """
        # Determine sender from envelope header
        sdap_header = envelope.get("sdap", {})
        sender_did = sdap_header.get("senderDID", session.initiator_did)

        return unwrap_a2a_message(
            wrapped=envelope,
            session=session,
            encrypt_key=session.encrypt_key,
        )


def _find_handshake_endpoint(did_doc: DIDDocument) -> str | None:
    """Find the SDAP handshake endpoint URL from a DID document."""
    for svc in did_doc.service:
        if svc.type == "SDAPHandshakeEndpoint":
            return svc.serviceEndpoint
    return None
