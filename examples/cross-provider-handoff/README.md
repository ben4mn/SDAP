# Example: Cross-Provider Handoff

Demonstrates a full SDAP handshake between two agents hosted at different
provider domains — `acme-health.com` and `city-hospital.org` — followed by
encrypted message exchange.

## What it shows

1. **DID setup** — each agent generates Ed25519 (auth) and X25519 (key-agreement)
   keypairs, then constructs a `did:sdap` DID document advertising its endpoints.
2. **Provider attestations** — each provider signs a JWT attestation for its
   agent, declaring capabilities, compliance tags (HIPAA), and security level.
3. **3-message handshake** — INIT → ACCEPT → CONFIRM with X25519 ephemeral
   key exchange and HKDF session-key derivation.
4. **Encrypted messaging** — a medical records query and response exchanged
   over the session using AES-256-GCM with replay protection.

## Run

```bash
cd sdap-python
PYTHONPATH=src python ../examples/cross-provider-handoff/example.py
```

## Key APIs used

```python
from sdap.identity import generate_ed25519_keypair, generate_x25519_keypair, create_did, create_attestation, verify_attestation
from sdap.handshake import create_handshake_init, process_handshake_init, create_handshake_confirm, process_handshake_confirm
from sdap.a2a import wrap_a2a_message, unwrap_a2a_message
```
