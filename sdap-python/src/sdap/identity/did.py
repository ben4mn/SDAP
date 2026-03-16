"""SDAP DID document creation, parsing, validation, and resolution."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import BaseModel, Field

from sdap.identity.keys import public_key_to_multibase

# Regex patterns derived from the JSON schema
_DID_PATTERN = re.compile(
    r"^did:sdap:([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})(?::([A-Za-z0-9\-_\.]+))?$"
)

_DID_CONTEXTS = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1",
    "https://sdap.dev/contexts/v1",
]


class VerificationMethod(BaseModel):
    id: str
    type: str
    controller: str
    publicKeyMultibase: str
    revoked: Optional[str] = None

    model_config = {"extra": "forbid"}


class ServiceEndpoint(BaseModel):
    id: str
    type: str
    serviceEndpoint: str

    model_config = {"extra": "forbid"}


class DIDDocument(BaseModel):
    context: list[str] = Field(alias="@context")
    id: str
    controller: str
    verificationMethod: list[VerificationMethod]
    authentication: list[str]
    keyAgreement: list[str]
    service: list[ServiceEndpoint]
    providerAttestation: Optional[str] = None
    created: str
    updated: str
    deactivated: Optional[bool] = None

    # Optional SDAP extension fields
    sdap_agentType: Optional[str] = Field(None, alias="sdap:agentType")
    sdap_fleetId: Optional[str] = Field(None, alias="sdap:fleetId")
    sdap_instanceId: Optional[str] = Field(None, alias="sdap:instanceId")
    sdap_supportedLayers: Optional[list[int]] = Field(None, alias="sdap:supportedLayers")
    sdap_minSecurityLevel: Optional[str] = Field(None, alias="sdap:minSecurityLevel")

    model_config = {"populate_by_name": True, "extra": "allow"}

    def model_dump_json_ld(self) -> dict:
        """Serialize to a JSON-LD-compatible dict (uses @context key)."""
        data = self.model_dump(by_alias=True, exclude_none=True)
        return data


def validate_did(did: str) -> bool:
    """Return True if *did* is a syntactically valid did:sdap DID."""
    return bool(_DID_PATTERN.match(did))


def parse_did(did: str) -> tuple[str, str]:
    """Extract ``(provider_domain, agent_id)`` from a did:sdap DID.

    For provider-only DIDs (no agent_id), ``agent_id`` is an empty string.

    Raises:
        ValueError: If the DID is not a valid did:sdap DID.
    """
    m = _DID_PATTERN.match(did)
    if not m:
        raise ValueError(f"Invalid did:sdap DID: {did!r}")
    provider_domain = m.group(1)
    agent_id = m.group(2) or ""
    return provider_domain, agent_id


def create_did(
    provider_domain: str,
    agent_id: str,
    auth_key: Ed25519PublicKey,
    agreement_key: X25519PublicKey,
    *,
    auth_key_id: str = "auth-key-1",
    agreement_key_id: str = "agree-key-1",
    a2a_endpoint: str | None = None,
    handshake_endpoint: str | None = None,
    provider_attestation: str | None = None,
    created: str | None = None,
    updated: str | None = None,
    extra_fields: dict[str, Any] | None = None,
) -> DIDDocument:
    """Construct a :class:`DIDDocument` for an SDAP agent.

    Args:
        provider_domain: e.g. ``"acme-health.com"``
        agent_id: e.g. ``"records-agent-v2"``
        auth_key: Ed25519 public key for authentication.
        agreement_key: X25519 public key for key agreement.
        auth_key_id: Fragment for the auth key (default ``"auth-key-1"``).
        agreement_key_id: Fragment for the agreement key (default ``"agree-key-1"``).
        a2a_endpoint: Optional HTTPS URL for the A2A agent endpoint.
        handshake_endpoint: Optional HTTPS URL for the SDAP handshake endpoint.
        provider_attestation: Optional compact JWT attestation.
        created: ISO 8601 creation timestamp (defaults to now).
        updated: ISO 8601 update timestamp (defaults to now).
        extra_fields: Additional fields merged into the document.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    created = created or now
    updated = updated or now

    did = f"did:sdap:{provider_domain}:{agent_id}"
    controller = f"did:sdap:{provider_domain}"

    auth_vm_id = f"{did}#{auth_key_id}"
    agree_vm_id = f"{did}#{agreement_key_id}"

    verification_methods = [
        VerificationMethod(
            id=auth_vm_id,
            type="Ed25519VerificationKey2020",
            controller=did,
            publicKeyMultibase=public_key_to_multibase(auth_key),
        ),
        VerificationMethod(
            id=agree_vm_id,
            type="X25519KeyAgreementKey2020",
            controller=did,
            publicKeyMultibase=public_key_to_multibase(agreement_key),
        ),
    ]

    services: list[ServiceEndpoint] = []
    if a2a_endpoint:
        services.append(
            ServiceEndpoint(
                id=f"{did}#a2a",
                type="A2AAgentEndpoint",
                serviceEndpoint=a2a_endpoint,
            )
        )
    if handshake_endpoint:
        services.append(
            ServiceEndpoint(
                id=f"{did}#handshake",
                type="SDAPHandshakeEndpoint",
                serviceEndpoint=handshake_endpoint,
            )
        )
    # Ensure at least 2 services per schema minItems=2
    while len(services) < 2:
        idx = len(services) + 1
        placeholder_url = f"https://{provider_domain}/sdap/service-{idx}"
        svc_type = "A2AAgentEndpoint" if idx == 1 else "SDAPHandshakeEndpoint"
        services.append(
            ServiceEndpoint(
                id=f"{did}#service-{idx}",
                type=svc_type,
                serviceEndpoint=placeholder_url,
            )
        )

    doc_data: dict[str, Any] = {
        "@context": _DID_CONTEXTS,
        "id": did,
        "controller": controller,
        "verificationMethod": [vm.model_dump(exclude_none=True) for vm in verification_methods],
        "authentication": [auth_vm_id],
        "keyAgreement": [agree_vm_id],
        "service": [s.model_dump(exclude_none=True) for s in services],
        "created": created,
        "updated": updated,
    }
    if provider_attestation:
        doc_data["providerAttestation"] = provider_attestation
    if extra_fields:
        doc_data.update(extra_fields)

    return DIDDocument.model_validate(doc_data)


async def resolve_did(did: str, http_client: httpx.AsyncClient) -> DIDDocument:
    """Resolve a did:sdap DID via the HTTPS .well-known endpoint.

    Fetches ``https://<provider_domain>/.well-known/sdap/did/<agent_id>``
    and returns the parsed :class:`DIDDocument`.

    Raises:
        ValueError: For invalid DID or non-2xx HTTP responses.
        httpx.HTTPError: For network-level errors.
    """
    provider_domain, agent_id = parse_did(did)
    if not agent_id:
        raise ValueError("Cannot resolve a provider-only DID (no agent_id)")

    url = f"https://{provider_domain}/.well-known/sdap/did/{agent_id}"
    response = await http_client.get(url)
    if response.status_code != 200:
        raise ValueError(
            f"DID resolution failed for {did}: HTTP {response.status_code}"
        )
    data = response.json()
    return DIDDocument.model_validate(data)
