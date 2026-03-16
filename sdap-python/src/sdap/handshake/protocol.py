"""SDAP 3-message handshake protocol."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from sdap.crypto import (
    derive_session_keys,
    perform_ecdh,
    sign_jws,
    verify_jws,
)
from sdap.identity.did import DIDDocument, validate_did
from sdap.identity.keys import (
    KeyPair,
    jwk_to_public_key,
    multibase_to_public_key,
    public_key_to_jwk,
)

_MAX_CLOCK_SKEW_SECONDS = 60


class HandshakeState(str, Enum):
    INIT_SENT = "INIT_SENT"
    ACCEPT_RECEIVED = "ACCEPT_RECEIVED"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"


@dataclass
class Session:
    session_id: str
    initiator_did: str
    responder_did: str
    encrypt_key: bytes
    mac_key: bytes
    granted_scopes: list[str]
    security_level: str
    expiry: datetime
    # Maps DID -> last received sequence number for messages FROM that DID (for replay detection)
    sequence_counter: dict[str, int] = field(default_factory=dict)
    # Maps DID -> last sent sequence number for messages BY that DID (for outgoing ordering)
    send_counter: dict[str, int] = field(default_factory=dict)

    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) >= self.expiry


def _now_ts() -> int:
    """Return current UTC time as a Unix timestamp integer."""
    return int(datetime.now(tz=timezone.utc).timestamp())


def _check_timestamp(ts: int) -> None:
    """Raise ValueError if timestamp is outside the allowed clock skew."""
    now = _now_ts()
    if abs(now - ts) > _MAX_CLOCK_SKEW_SECONDS:
        raise ValueError(
            f"Timestamp {ts} is outside allowed clock skew ({_MAX_CLOCK_SKEW_SECONDS}s)"
        )


def _get_auth_public_key(did_doc: DIDDocument):
    """Extract the Ed25519 auth public key from a DIDDocument."""
    if not did_doc.authentication:
        raise ValueError(f"DID document {did_doc.id} has no authentication keys")
    auth_key_id = did_doc.authentication[0]
    # auth_key_id may be a full reference like "did:sdap:...#auth-key-1"
    for vm in did_doc.verificationMethod:
        if vm.id == auth_key_id:
            return multibase_to_public_key(vm.publicKeyMultibase, "Ed25519")
    raise ValueError(f"Auth key {auth_key_id} not found in verification methods")


def _get_agreement_public_key(did_doc: DIDDocument):
    """Extract the X25519 key agreement public key from a DIDDocument."""
    if not did_doc.keyAgreement:
        raise ValueError(f"DID document {did_doc.id} has no key agreement keys")
    agree_key_id = did_doc.keyAgreement[0]
    for vm in did_doc.verificationMethod:
        if vm.id == agree_key_id:
            return multibase_to_public_key(vm.publicKeyMultibase, "X25519")
    raise ValueError(f"Agreement key {agree_key_id} not found in verification methods")


def create_handshake_init(
    initiator_did: str,
    target_did: str,
    auth_private_key: Ed25519PrivateKey,
    auth_key_id: str,
    ephemeral_keypair: KeyPair,
    requested_scopes: list[str],
    required_security_level: str = "standard",
) -> tuple[dict, X25519PrivateKey]:
    """Create a handshake INIT message.

    Returns:
        (init_message_dict, ephemeral_private_key)
    """
    if not validate_did(initiator_did):
        raise ValueError(f"Invalid initiator DID: {initiator_did!r}")
    if not validate_did(target_did):
        raise ValueError(f"Invalid target DID: {target_did!r}")

    nonce = os.urandom(32).hex()
    session_id = str(uuid.uuid4())

    payload = {
        "type": "sdap-handshake-init",
        "version": "1.0",
        "sessionId": session_id,
        "initiatorDID": initiator_did,
        "targetDID": target_did,
        "nonce": nonce,
        "timestamp": _now_ts(),
        "ephemeralKey": public_key_to_jwk(ephemeral_keypair.public_key),
        "requestedScopes": requested_scopes,
        "requiredSecurityLevel": required_security_level,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    jws = sign_jws(payload_bytes, auth_private_key, auth_key_id)

    init_msg = {
        "type": "sdap-handshake-init",
        "jws": jws,
    }
    return init_msg, ephemeral_keypair.private_key


def process_handshake_init(
    init_msg: dict,
    responder_did: str,
    responder_auth_key: Ed25519PrivateKey,
    responder_auth_key_id: str,
    responder_ephemeral: KeyPair,
    resolve_did_func: Callable[[str], DIDDocument],
    granted_scopes: list[str] | None = None,
    session_ttl: int = 3600,
) -> tuple[dict, Session]:
    """Validate an INIT message, produce an ACCEPT message, and derive session keys.

    Returns:
        (accept_msg_dict, session)
    """
    jws = init_msg.get("jws")
    if not jws:
        raise ValueError("Missing 'jws' in init message")

    # Decode without verification first to extract initiator DID
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWS format in init message")

    import base64 as _b64
    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload_bytes = _b64.urlsafe_b64decode(payload_b64)
    payload = json.loads(payload_bytes)

    initiator_did = payload.get("initiatorDID")
    if not initiator_did or not validate_did(initiator_did):
        raise ValueError(f"Invalid initiatorDID in INIT payload: {initiator_did!r}")

    # Resolve initiator DID to get their auth public key
    initiator_doc = resolve_did_func(initiator_did)
    initiator_auth_key = _get_auth_public_key(initiator_doc)

    # Verify signature
    try:
        verify_jws(jws, initiator_auth_key)
    except ValueError as exc:
        raise ValueError(f"INIT message signature verification failed: {exc}") from exc

    # Validate fields
    if payload.get("type") != "sdap-handshake-init":
        raise ValueError("Invalid message type in INIT payload")
    if payload.get("targetDID") != responder_did:
        raise ValueError(
            f"targetDID mismatch: expected {responder_did!r}, got {payload.get('targetDID')!r}"
        )
    _check_timestamp(payload["timestamp"])

    session_id = payload["sessionId"]
    initiator_nonce = payload["nonce"]
    initiator_ephemeral_key = jwk_to_public_key(payload["ephemeralKey"])
    requested_scopes = payload.get("requestedScopes", [])

    # Determine granted scopes (default: grant all requested)
    if granted_scopes is None:
        granted_scopes = requested_scopes

    # ECDH with initiator's ephemeral key
    shared_secret = perform_ecdh(responder_ephemeral.private_key, initiator_ephemeral_key)

    responder_nonce = os.urandom(32).hex()

    # Derive session keys
    encrypt_key, mac_key = derive_session_keys(
        shared_secret,
        bytes.fromhex(initiator_nonce) if len(initiator_nonce) == 64 else initiator_nonce.encode(),
        responder_nonce.encode(),
        session_id,
    )

    expiry = datetime.fromtimestamp(
        _now_ts() + session_ttl, tz=timezone.utc
    )
    session = Session(
        session_id=session_id,
        initiator_did=initiator_did,
        responder_did=responder_did,
        encrypt_key=encrypt_key,
        mac_key=mac_key,
        granted_scopes=granted_scopes,
        security_level=payload.get("requiredSecurityLevel", "standard"),
        expiry=expiry,
        sequence_counter={initiator_did: 0, responder_did: 0},
    )

    # Build accept payload
    accept_payload = {
        "type": "sdap-handshake-accept",
        "version": "1.0",
        "sessionId": session_id,
        "initiatorDID": initiator_did,
        "responderDID": responder_did,
        "initiatorNonce": initiator_nonce,
        "responderNonce": responder_nonce,
        "timestamp": _now_ts(),
        "ephemeralKey": public_key_to_jwk(responder_ephemeral.public_key),
        "grantedScopes": granted_scopes,
        "securityLevel": session.security_level,
        "sessionExpiry": int(expiry.timestamp()),
    }
    accept_payload_bytes = json.dumps(accept_payload, separators=(",", ":")).encode("utf-8")
    accept_jws = sign_jws(accept_payload_bytes, responder_auth_key, responder_auth_key_id)

    accept_msg = {
        "type": "sdap-handshake-accept",
        "jws": accept_jws,
    }
    return accept_msg, session


def create_handshake_confirm(
    accept_msg: dict,
    initiator_did: str,
    initiator_nonce: str,
    auth_private_key: Ed25519PrivateKey,
    auth_key_id: str,
    initiator_ephemeral_private: X25519PrivateKey,
) -> tuple[dict, Session]:
    """Process an ACCEPT message and produce a CONFIRM message.

    Returns:
        (confirm_msg_dict, session)
    """
    jws = accept_msg.get("jws")
    if not jws:
        raise ValueError("Missing 'jws' in accept message")

    # Decode payload without verification to extract responder DID
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWS format in accept message")

    import base64 as _b64
    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload_bytes = _b64.urlsafe_b64decode(payload_b64)
    payload = json.loads(payload_bytes)

    if payload.get("type") != "sdap-handshake-accept":
        raise ValueError("Invalid message type in ACCEPT payload")

    responder_did = payload.get("responderDID")
    if not responder_did or not validate_did(responder_did):
        raise ValueError(f"Invalid responderDID in ACCEPT payload: {responder_did!r}")

    # Validate the nonce echo
    if payload.get("initiatorDID") != initiator_did:
        raise ValueError("initiatorDID mismatch in ACCEPT message")
    if payload.get("initiatorNonce") != initiator_nonce:
        raise ValueError("Nonce mismatch in ACCEPT message: initiator nonce not echoed correctly")

    _check_timestamp(payload["timestamp"])

    session_id = payload["sessionId"]
    responder_nonce = payload["responderNonce"]
    responder_ephemeral_key = jwk_to_public_key(payload["ephemeralKey"])
    granted_scopes = payload.get("grantedScopes", [])
    security_level = payload.get("securityLevel", "standard")
    session_expiry_ts = payload.get("sessionExpiry")

    if session_expiry_ts:
        expiry = datetime.fromtimestamp(session_expiry_ts, tz=timezone.utc)
    else:
        expiry = datetime.fromtimestamp(_now_ts() + 3600, tz=timezone.utc)

    # ECDH and key derivation
    shared_secret = perform_ecdh(initiator_ephemeral_private, responder_ephemeral_key)
    encrypt_key, mac_key = derive_session_keys(
        shared_secret,
        bytes.fromhex(initiator_nonce) if len(initiator_nonce) == 64 else initiator_nonce.encode(),
        responder_nonce.encode(),
        session_id,
    )

    session = Session(
        session_id=session_id,
        initiator_did=initiator_did,
        responder_did=responder_did,
        encrypt_key=encrypt_key,
        mac_key=mac_key,
        granted_scopes=granted_scopes,
        security_level=security_level,
        expiry=expiry,
        sequence_counter={initiator_did: 0, responder_did: 0},
    )

    # Build confirm payload
    confirm_payload = {
        "type": "sdap-handshake-confirm",
        "version": "1.0",
        "sessionId": session_id,
        "initiatorDID": initiator_did,
        "responderDID": responder_did,
        "responderNonce": responder_nonce,
        "timestamp": _now_ts(),
    }
    confirm_payload_bytes = json.dumps(confirm_payload, separators=(",", ":")).encode("utf-8")
    confirm_jws = sign_jws(confirm_payload_bytes, auth_private_key, auth_key_id)

    confirm_msg = {
        "type": "sdap-handshake-confirm",
        "jws": confirm_jws,
    }
    return confirm_msg, session


def process_handshake_confirm(
    confirm_msg: dict,
    session: Session,
    resolve_did_func: Callable[[str], DIDDocument],
) -> Session:
    """Validate a CONFIRM message and return the confirmed session.

    Returns:
        Session (same object, validated)
    """
    jws = confirm_msg.get("jws")
    if not jws:
        raise ValueError("Missing 'jws' in confirm message")

    # Decode payload
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWS format in confirm message")

    import base64 as _b64
    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload_bytes = _b64.urlsafe_b64decode(payload_b64)
    payload = json.loads(payload_bytes)

    if payload.get("type") != "sdap-handshake-confirm":
        raise ValueError("Invalid message type in CONFIRM payload")

    if payload.get("sessionId") != session.session_id:
        raise ValueError("Session ID mismatch in CONFIRM message")
    if payload.get("initiatorDID") != session.initiator_did:
        raise ValueError("initiatorDID mismatch in CONFIRM message")
    if payload.get("responderDID") != session.responder_did:
        raise ValueError("responderDID mismatch in CONFIRM message")

    _check_timestamp(payload["timestamp"])

    if session.is_expired():
        raise ValueError("Session has expired before confirmation")

    # Verify signature using initiator's auth key
    initiator_doc = resolve_did_func(session.initiator_did)
    initiator_auth_key = _get_auth_public_key(initiator_doc)

    try:
        verify_jws(jws, initiator_auth_key)
    except ValueError as exc:
        raise ValueError(f"CONFIRM message signature verification failed: {exc}") from exc

    return session
