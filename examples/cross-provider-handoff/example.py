"""
SDAP Example 1: Cross-Provider Handoff
=======================================
Two agents from different providers (acme-health.com and city-hospital.org)
perform a full SDAP handshake and exchange encrypted medical records queries.

Run with:
    cd sdap-python && PYTHONPATH=src python ../examples/cross-provider-handoff/example.py
"""

from __future__ import annotations

import base64
import json

from sdap.identity import (
    create_attestation,
    create_did,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    verify_attestation,
)
from sdap.handshake import (
    create_handshake_confirm,
    create_handshake_init,
    process_handshake_confirm,
    process_handshake_init,
)
from sdap.a2a import wrap_a2a_message, unwrap_a2a_message

SEPARATOR = "-" * 60


def _decode_jws_payload(jws: str) -> dict:
    parts = jws.split(".")
    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def main() -> None:
    print(SEPARATOR)
    print("SDAP Example: Cross-Provider Handoff")
    print(SEPARATOR)

    # ------------------------------------------------------------------ #
    # Step 1: Set up two agents at different providers                    #
    # ------------------------------------------------------------------ #
    print("\n[1] Setting up agents at acme-health.com and city-hospital.org")

    # ACME Health — records retrieval agent
    acme_auth_kp   = generate_ed25519_keypair("auth-key-1")
    acme_agree_kp  = generate_x25519_keypair("agree-key-1")
    acme_did_doc   = create_did(
        provider_domain="acme-health.com",
        agent_id="records-agent",
        auth_key=acme_auth_kp.public_key,
        agreement_key=acme_agree_kp.public_key,
        a2a_endpoint="https://acme-health.com/a2a",
        handshake_endpoint="https://acme-health.com/sdap/handshake",
    )
    acme_did = acme_did_doc.id
    print(f"   ACME Health agent DID : {acme_did}")

    # City Hospital — EHR integration agent
    city_auth_kp   = generate_ed25519_keypair("auth-key-1")
    city_agree_kp  = generate_x25519_keypair("agree-key-1")
    city_did_doc   = create_did(
        provider_domain="city-hospital.org",
        agent_id="ehr-agent",
        auth_key=city_auth_kp.public_key,
        agreement_key=city_agree_kp.public_key,
        a2a_endpoint="https://city-hospital.org/a2a",
        handshake_endpoint="https://city-hospital.org/sdap/handshake",
    )
    city_did = city_did_doc.id
    print(f"   City Hospital agent DID: {city_did}")

    # ------------------------------------------------------------------ #
    # Step 2: Provider attestations                                       #
    # ------------------------------------------------------------------ #
    print("\n[2] Creating and verifying provider attestations")

    # ACME Health provider issues attestation for its agent
    acme_provider_kp = generate_ed25519_keypair("acme-provider-key")
    acme_provider_did = "did:sdap:acme-health.com"

    acme_attestation = create_attestation(
        issuer_did=acme_provider_did,
        subject_did=acme_did,
        private_key=acme_provider_kp.private_key,
        agent_type="records-retrieval",
        capabilities=["patient-data:read", "medical-records:query"],
        security_level="standard",
        compliance_tags=["HIPAA"],
        max_delegation_depth=2,
    )

    # City Hospital provider issues attestation for its agent
    city_provider_kp = generate_ed25519_keypair("city-provider-key")
    city_provider_did = "did:sdap:city-hospital.org"

    city_attestation = create_attestation(
        issuer_did=city_provider_did,
        subject_did=city_did,
        private_key=city_provider_kp.private_key,
        agent_type="ehr-integration",
        capabilities=["patient-data:read", "patient-data:write", "lab-results:read"],
        security_level="standard",
        compliance_tags=["HIPAA", "HL7-FHIR"],
        max_delegation_depth=1,
    )

    # Verify attestations
    verified_acme = verify_attestation(acme_attestation, acme_provider_kp.public_key)
    verified_city = verify_attestation(city_attestation, city_provider_kp.public_key)
    print(f"   ACME attestation verified  : agent_type={verified_acme.sdap_attestation.agentType!r}, "
          f"compliance={verified_acme.sdap_attestation.complianceTags}")
    print(f"   City attestation verified  : agent_type={verified_city.sdap_attestation.agentType!r}, "
          f"compliance={verified_city.sdap_attestation.complianceTags}")

    # ------------------------------------------------------------------ #
    # Step 3: SDAP Handshake — INIT                                       #
    # ------------------------------------------------------------------ #
    print("\n[3] Handshake INIT — ACME Health initiates connection to City Hospital")

    eph_acme = generate_x25519_keypair("eph-acme")
    init_msg, eph_acme_private = create_handshake_init(
        initiator_did=acme_did,
        target_did=city_did,
        auth_private_key=acme_auth_kp.private_key,
        auth_key_id=acme_auth_kp.key_id,
        ephemeral_keypair=eph_acme,
        requested_scopes=["patient-data:read", "lab-results:read"],
        required_security_level="standard",
    )

    init_payload = _decode_jws_payload(init_msg["jws"])
    initiator_nonce = init_payload["nonce"]
    print(f"   Session ID       : {init_payload['sessionId']}")
    print(f"   Requested scopes : {init_payload['requestedScopes']}")
    print(f"   Security level   : {init_payload['requiredSecurityLevel']}")

    # ------------------------------------------------------------------ #
    # Step 4: SDAP Handshake — ACCEPT                                     #
    # ------------------------------------------------------------------ #
    print("\n[4] Handshake ACCEPT — City Hospital processes INIT and replies")

    # City Hospital builds a simple DID resolver from its local store
    did_store = {
        acme_did: acme_did_doc,
        city_did: city_did_doc,
    }

    def resolve_did(did: str):
        if did not in did_store:
            raise ValueError(f"DID not found: {did!r}")
        return did_store[did]

    eph_city = generate_x25519_keypair("eph-city")
    accept_msg, city_session = process_handshake_init(
        init_msg=init_msg,
        responder_did=city_did,
        responder_auth_key=city_auth_kp.private_key,
        responder_auth_key_id=city_auth_kp.key_id,
        responder_ephemeral=eph_city,
        resolve_did_func=resolve_did,
        granted_scopes=["patient-data:read", "lab-results:read"],
    )

    accept_payload = _decode_jws_payload(accept_msg["jws"])
    print(f"   Granted scopes   : {accept_payload['grantedScopes']}")
    print(f"   Session expiry   : {accept_payload['sessionExpiry']}")
    print(f"   City session key : {city_session.encrypt_key[:8].hex()}... (AES-256-GCM)")

    # ------------------------------------------------------------------ #
    # Step 5: SDAP Handshake — CONFIRM                                    #
    # ------------------------------------------------------------------ #
    print("\n[5] Handshake CONFIRM — ACME Health completes the handshake")

    confirm_msg, acme_session = create_handshake_confirm(
        accept_msg=accept_msg,
        initiator_did=acme_did,
        initiator_nonce=initiator_nonce,
        auth_private_key=acme_auth_kp.private_key,
        auth_key_id=acme_auth_kp.key_id,
        initiator_ephemeral_private=eph_acme_private,
    )

    # City Hospital validates the CONFIRM
    process_handshake_confirm(
        confirm_msg=confirm_msg,
        session=city_session,
        resolve_did_func=resolve_did,
    )

    # Both sides must derive the same session key
    keys_match = acme_session.encrypt_key == city_session.encrypt_key
    print(f"   Session keys match : {keys_match}")
    print(f"   Session ID         : {acme_session.session_id}")
    assert keys_match, "Session keys must match after handshake"

    # ------------------------------------------------------------------ #
    # Step 6: Encrypted message exchange                                  #
    # ------------------------------------------------------------------ #
    print("\n[6] Encrypted message exchange over the established session")

    # ACME Health sends a medical records query
    query = {
        "action": "query-patient-records",
        "patientId": "P-20240101-007",
        "dataTypes": ["demographics", "lab-results", "medications"],
        "requestingProvider": "acme-health.com",
    }

    encrypted_query = wrap_a2a_message(
        message=query,
        session=acme_session,
        encrypt_key=acme_session.encrypt_key,
        sender_did=acme_did,
    )

    print(f"   Query sent (encrypted)   : payload length = {len(encrypted_query['payload'])} chars")
    print(f"   Sequence number          : {encrypted_query['sdap']['sequenceNumber']}")
    print(f"   Audit hash               : {encrypted_query['sdap']['auditHash'][:16]}...")

    # City Hospital decrypts and processes the query
    decrypted_query = unwrap_a2a_message(
        wrapped=encrypted_query,
        session=city_session,
        encrypt_key=city_session.encrypt_key,
    )

    assert decrypted_query == query, "Decrypted query must match original"
    print(f"   Query decrypted OK       : action={decrypted_query['action']!r}, "
          f"patientId={decrypted_query['patientId']!r}")

    # City Hospital sends back a response with patient data
    response = {
        "action": "patient-records-response",
        "patientId": "P-20240101-007",
        "status": "found",
        "records": {
            "demographics": {"name": "Jane Doe", "dob": "1985-03-12", "gender": "F"},
            "labResults": [
                {"test": "HbA1c", "value": "5.4%", "date": "2024-01-10", "status": "normal"},
                {"test": "CholesterolTotal", "value": "190mg/dL", "date": "2024-01-10", "status": "normal"},
            ],
            "medications": ["metformin 500mg", "lisinopril 10mg"],
        },
        "dataClassification": "PHI",
    }

    encrypted_response = wrap_a2a_message(
        message=response,
        session=city_session,
        encrypt_key=city_session.encrypt_key,
        sender_did=city_did,
    )

    print(f"\n   Response sent (encrypted) : payload length = {len(encrypted_response['payload'])} chars")

    # ACME Health decrypts the response
    decrypted_response = unwrap_a2a_message(
        wrapped=encrypted_response,
        session=acme_session,
        encrypt_key=acme_session.encrypt_key,
    )

    assert decrypted_response == response, "Decrypted response must match original"
    print(f"   Response decrypted OK     : status={decrypted_response['status']!r}, "
          f"records={list(decrypted_response['records'].keys())}")

    # ------------------------------------------------------------------ #
    # Summary                                                             #
    # ------------------------------------------------------------------ #
    print(f"\n{SEPARATOR}")
    print("Summary")
    print(SEPARATOR)
    print(f"  Initiator : {acme_did}")
    print(f"  Responder : {city_did}")
    print(f"  Session   : {acme_session.session_id}")
    print(f"  Scopes    : {acme_session.granted_scopes}")
    print(f"  Cipher    : AES-256-GCM (session key derived via X25519 ECDH + HKDF)")
    print(f"  Auth      : Ed25519 signatures on all handshake messages")
    print(f"  Status    : Handshake complete, 2 encrypted messages exchanged successfully")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
