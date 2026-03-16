"""
SDAP Example 3: Medical Records with HIPAA Compliance and Audit Trail
======================================================================
Demonstrates PHI handling, HIPAA compliance tags, high-security sessions,
data-classification enforcement in delegation, and a full tamper-evident
audit chain.

  Provider   : regional-health.net  (requesting agent)
  EHR System : ehr-system.com       (records agent)

Run with:
    cd sdap-python && PYTHONPATH=src python ../examples/medical-records/example.py
"""

from __future__ import annotations

import base64
import json
import time

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
from sdap.delegation import (
    DelegationConstraints,
    create_delegation_token,
    decode_delegation_token,
    validate_delegation_chain,
)
from sdap.audit import (
    create_audit_entry,
    verify_audit_chain,
    AuditEntry,
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
    print("SDAP Example: Medical Records — HIPAA + PHI + Audit Chain")
    print(SEPARATOR)

    # ------------------------------------------------------------------ #
    # Step 1: Set up agents with HIPAA compliance tags                    #
    # ------------------------------------------------------------------ #
    print("\n[1] Setting up HIPAA-compliant agents")

    # Regional Health — care-coordination agent
    rh_auth_kp  = generate_ed25519_keypair("auth-key-1")
    rh_agree_kp = generate_x25519_keypair("agree-key-1")
    rh_did_doc  = create_did(
        provider_domain="regional-health.net",
        agent_id="care-coordinator",
        auth_key=rh_auth_kp.public_key,
        agreement_key=rh_agree_kp.public_key,
        a2a_endpoint="https://regional-health.net/a2a",
        handshake_endpoint="https://regional-health.net/sdap/handshake",
    )
    rh_did = rh_did_doc.id

    # EHR System — patient records agent
    ehr_auth_kp  = generate_ed25519_keypair("auth-key-1")
    ehr_agree_kp = generate_x25519_keypair("agree-key-1")
    ehr_did_doc  = create_did(
        provider_domain="ehr-system.com",
        agent_id="records-agent",
        auth_key=ehr_auth_kp.public_key,
        agreement_key=ehr_agree_kp.public_key,
        a2a_endpoint="https://ehr-system.com/a2a",
        handshake_endpoint="https://ehr-system.com/sdap/handshake",
    )
    ehr_did = ehr_did_doc.id

    print(f"   Regional Health DID : {rh_did}")
    print(f"   EHR System DID      : {ehr_did}")

    # ------------------------------------------------------------------ #
    # Step 2: HIPAA attestations                                          #
    # ------------------------------------------------------------------ #
    print("\n[2] Issuing HIPAA-tagged provider attestations")

    rh_provider_kp  = generate_ed25519_keypair("rh-provider")
    rh_provider_did = "did:sdap:regional-health.net"

    ehr_provider_kp  = generate_ed25519_keypair("ehr-provider")
    ehr_provider_did = "did:sdap:ehr-system.com"

    rh_attestation = create_attestation(
        issuer_did=rh_provider_did,
        subject_did=rh_did,
        private_key=rh_provider_kp.private_key,
        agent_type="care-coordinator",
        capabilities=["patient-data:read", "care-plan:read", "referral:write"],
        security_level="high",
        compliance_tags=["HIPAA", "HITECH", "SOC2"],
        max_delegation_depth=2,
    )

    ehr_attestation = create_attestation(
        issuer_did=ehr_provider_did,
        subject_did=ehr_did,
        private_key=ehr_provider_kp.private_key,
        agent_type="ehr-records",
        capabilities=["patient-data:read", "patient-data:write", "lab-results:read",
                      "imaging:read", "prescriptions:read"],
        security_level="high",
        compliance_tags=["HIPAA", "HITECH", "HL7-FHIR", "SOC2"],
        max_delegation_depth=1,
    )

    verified_rh  = verify_attestation(rh_attestation, rh_provider_kp.public_key)
    verified_ehr = verify_attestation(ehr_attestation, ehr_provider_kp.public_key)

    print(f"   Regional Health attestation : securityLevel={verified_rh.sdap_attestation.securityLevel!r}, "
          f"tags={verified_rh.sdap_attestation.complianceTags}")
    print(f"   EHR System attestation      : securityLevel={verified_ehr.sdap_attestation.securityLevel!r}, "
          f"tags={verified_ehr.sdap_attestation.complianceTags}")

    # Verify HIPAA tag present on both
    assert "HIPAA" in verified_rh.sdap_attestation.complianceTags, "HIPAA tag required on Regional Health"
    assert "HIPAA" in verified_ehr.sdap_attestation.complianceTags, "HIPAA tag required on EHR System"
    print(f"   HIPAA compliance tag verified on both agents")

    # ------------------------------------------------------------------ #
    # Step 3: High-security handshake                                     #
    # ------------------------------------------------------------------ #
    print("\n[3] Establishing high-security SDAP session")

    did_store = {rh_did: rh_did_doc, ehr_did: ehr_did_doc}

    def resolve_did(did: str):
        if did not in did_store:
            raise ValueError(f"DID not found: {did!r}")
        return did_store[did]

    eph_rh = generate_x25519_keypair("eph-rh")
    init_msg, eph_rh_private = create_handshake_init(
        initiator_did=rh_did,
        target_did=ehr_did,
        auth_private_key=rh_auth_kp.private_key,
        auth_key_id=rh_auth_kp.key_id,
        ephemeral_keypair=eph_rh,
        requested_scopes=["patient-data:read", "lab-results:read", "imaging:read"],
        required_security_level="high",
    )

    init_payload = _decode_jws_payload(init_msg["jws"])
    initiator_nonce = init_payload["nonce"]
    session_id = init_payload["sessionId"]

    print(f"   Session ID        : {session_id}")
    print(f"   Required level    : {init_payload['requiredSecurityLevel']}")

    eph_ehr = generate_x25519_keypair("eph-ehr")
    accept_msg, ehr_session = process_handshake_init(
        init_msg=init_msg,
        responder_did=ehr_did,
        responder_auth_key=ehr_auth_kp.private_key,
        responder_auth_key_id=ehr_auth_kp.key_id,
        responder_ephemeral=eph_ehr,
        resolve_did_func=resolve_did,
        granted_scopes=["patient-data:read", "lab-results:read", "imaging:read"],
    )

    confirm_msg, rh_session = create_handshake_confirm(
        accept_msg=accept_msg,
        initiator_did=rh_did,
        initiator_nonce=initiator_nonce,
        auth_private_key=rh_auth_kp.private_key,
        auth_key_id=rh_auth_kp.key_id,
        initiator_ephemeral_private=eph_rh_private,
    )

    process_handshake_confirm(
        confirm_msg=confirm_msg,
        session=ehr_session,
        resolve_did_func=resolve_did,
    )

    assert rh_session.encrypt_key == ehr_session.encrypt_key
    print(f"   Security level    : {rh_session.security_level}")
    print(f"   Handshake done    : session keys match = True")

    # ------------------------------------------------------------------ #
    # Step 4: PHI delegation with classification enforcement             #
    # ------------------------------------------------------------------ #
    print("\n[4] Creating PHI delegation with HIPAA constraints")

    # A sub-system agent (did_sub) needs a delegated token to access lab results
    kp_sub = generate_ed25519_keypair("auth-key-1")
    did_sub = "did:sdap:regional-health.net:lab-processor"

    now = int(time.time())
    phi_constraints = DelegationConstraints(
        maxUses=5,
        notAfter=now + 1800,           # 30-minute window only
        allowedResources=["patient/*/lab-results"],
        requireMFA=True,
        dataClassification="PHI",      # must remain PHI throughout chain
    )

    phi_token = create_delegation_token(
        issuer_did=rh_did,
        delegatee_did=did_sub,
        audience_did=ehr_did,
        private_key=rh_auth_kp.private_key,
        scopes=["lab-results:read"],
        constraints=phi_constraints,
        delegation_depth=0,
    )

    phi_payload = decode_delegation_token(phi_token, rh_auth_kp.public_key)

    # Validate chain
    key_store = {rh_did: rh_auth_kp.public_key, did_sub: kp_sub.public_key}

    def resolve_key(did: str):
        if did not in key_store:
            raise ValueError(f"Key not found for DID: {did!r}")
        return key_store[did]

    leaf = validate_delegation_chain([phi_token], resolve_key)

    print(f"   Token JTI         : {phi_payload.jti}")
    print(f"   Scopes            : {phi_payload.scopes}")
    print(f"   dataClassif.      : {phi_payload.constraints.dataClassification}")
    print(f"   requireMFA        : {phi_payload.constraints.requireMFA}")
    print(f"   maxUses           : {phi_payload.constraints.maxUses}")
    print(f"   Chain valid       : True")

    # ------------------------------------------------------------------ #
    # Step 5: Encrypted PHI message exchange                              #
    # ------------------------------------------------------------------ #
    print("\n[5] Exchanging encrypted PHI over the high-security session")

    phi_request = {
        "action": "fetch-lab-results",
        "patientId": "P-HIPAA-20240115-042",
        "labTypes": ["CBC", "CMP", "HbA1c", "lipid-panel"],
        "requestingProvider": "regional-health.net",
        "purpose": "care-coordination",
        "dataClassification": "PHI",
    }

    encrypted_phi = wrap_a2a_message(
        message=phi_request,
        session=rh_session,
        encrypt_key=rh_session.encrypt_key,
        sender_did=rh_did,
    )

    print(f"   PHI request encrypted : {len(encrypted_phi['payload'])} chars (AES-256-GCM)")

    decrypted_phi = unwrap_a2a_message(
        wrapped=encrypted_phi,
        session=ehr_session,
        encrypt_key=ehr_session.encrypt_key,
    )

    assert decrypted_phi == phi_request
    assert decrypted_phi["dataClassification"] == "PHI"
    print(f"   PHI request decrypted : patientId={decrypted_phi['patientId']!r}, "
          f"classification={decrypted_phi['dataClassification']!r}")

    phi_response = {
        "action": "lab-results-response",
        "patientId": "P-HIPAA-20240115-042",
        "dataClassification": "PHI",
        "results": [
            {"test": "CBC-WBC",   "value": "6.2 K/uL",  "ref": "4.5-11.0",  "flag": "normal"},
            {"test": "CBC-RBC",   "value": "4.8 M/uL",  "ref": "4.2-5.4",   "flag": "normal"},
            {"test": "HbA1c",     "value": "6.1%",       "ref": "<5.7%",     "flag": "elevated"},
            {"test": "LDL",       "value": "128 mg/dL",  "ref": "<100",      "flag": "elevated"},
        ],
    }

    encrypted_response = wrap_a2a_message(
        message=phi_response,
        session=ehr_session,
        encrypt_key=ehr_session.encrypt_key,
        sender_did=ehr_did,
    )

    decrypted_response = unwrap_a2a_message(
        wrapped=encrypted_response,
        session=rh_session,
        encrypt_key=rh_session.encrypt_key,
    )

    assert decrypted_response == phi_response
    print(f"   PHI response decrypted: {len(decrypted_response['results'])} lab results received")

    # ------------------------------------------------------------------ #
    # Step 6: Build tamper-evident audit chain                            #
    # ------------------------------------------------------------------ #
    print("\n[6] Building HIPAA-compliant audit trail")

    audit_entries: list[AuditEntry] = []
    prev_hash: str | None = None

    audit_events = [
        ("session.initiated", {
            "sessionId": session_id,
            "initiatorDID": rh_did,
            "responderDID": ehr_did,
            "securityLevel": "high",
            "complianceTags": ["HIPAA"],
        }),
        ("session.established", {
            "sessionId": session_id,
            "grantedScopes": rh_session.granted_scopes,
            "keyAgreement": "X25519-ECDH-HKDF",
        }),
        ("phi.access.requested", {
            "sessionId": session_id,
            "patientId": "P-HIPAA-20240115-042",
            "requestType": "lab-results",
            "purpose": "care-coordination",
        }),
        ("phi.access.granted", {
            "sessionId": session_id,
            "patientId": "P-HIPAA-20240115-042",
            "labCount": len(phi_response["results"]),
            "dataClassification": "PHI",
        }),
        ("delegation.created", {
            "tokenId": phi_payload.jti,
            "scopes": phi_payload.scopes,
            "delegatee": did_sub,
            "requireMFA": True,
        }),
        ("session.closed", {
            "sessionId": session_id,
            "messageCount": 2,
        }),
    ]

    for event_type, event_data in audit_events:
        entry = create_audit_entry(
            actor_did=rh_did,
            event_type=event_type,
            event_data=event_data,
            private_key=rh_auth_kp.private_key,
            key_id=rh_auth_kp.key_id,
            previous_hash=prev_hash,
            session_id=session_id,
        )
        audit_entries.append(entry)
        prev_hash = entry.entryHash
        print(f"   [{len(audit_entries):02d}] {event_type:<30} hash={entry.entryHash[:12]}...")

    # ------------------------------------------------------------------ #
    # Step 7: Verify the audit chain                                      #
    # ------------------------------------------------------------------ #
    print("\n[7] Verifying tamper-evident audit chain")

    audit_key_store = {rh_did: rh_auth_kp.public_key}

    def resolve_audit_key(did: str):
        if did not in audit_key_store:
            raise ValueError(f"Audit key not found for DID: {did!r}")
        return audit_key_store[did]

    chain_valid = verify_audit_chain(audit_entries, resolve_audit_key)
    print(f"   Entries in chain      : {len(audit_entries)}")
    print(f"   Chain integrity       : {chain_valid}")
    print(f"   Hash chain linked     : {all(audit_entries[i].previousHash == audit_entries[i-1].entryHash for i in range(1, len(audit_entries)))}")
    print(f"   All signatures valid  : True  (Ed25519)")

    # Demonstrate tamper detection
    print("\n   Testing tamper detection...")
    tampered_entries = list(audit_entries)
    original_entry = tampered_entries[2]
    tampered = original_entry.model_copy(update={
        "eventData": {**original_entry.eventData, "patientId": "P-TAMPERED"}
    })
    tampered_entries[2] = tampered
    try:
        verify_audit_chain(tampered_entries, resolve_audit_key)
        print("   ERROR: tampered chain should have been rejected")
    except ValueError as exc:
        print(f"   Tamper detected correctly: {str(exc)[:55]}...")

    # ------------------------------------------------------------------ #
    # Summary                                                             #
    # ------------------------------------------------------------------ #
    print(f"\n{SEPARATOR}")
    print("Summary")
    print(SEPARATOR)
    print(f"  Agents          : {rh_did}")
    print(f"                    {ehr_did}")
    print(f"  Security level  : high")
    print(f"  Compliance tags : HIPAA, HITECH, SOC2, HL7-FHIR")
    print(f"  Delegation      : PHI-classified, requireMFA=True, maxUses=5")
    print(f"  PHI messages    : 2 encrypted (AES-256-GCM)")
    print(f"  Audit entries   : {len(audit_entries)} (tamper-evident, Ed25519-signed)")
    print(f"  Status          : All HIPAA compliance checks passed")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
