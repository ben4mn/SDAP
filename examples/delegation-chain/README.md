# Example: Delegation Chain

Demonstrates SDAP's hierarchical delegation model with three agents across
three provider domains.

## What it shows

1. **Agent setup** — three agents (`orchestrator.net`, `specialist.org`,
   `subspec.io`) with independent Ed25519 keypairs.
2. **Root delegation** — Agent A grants Agent B scopes
   `["patient-data:read", "lab-results:read", "audit:read"]` with constraints
   (maxUses=100, 24-hour expiry, no MFA required).
3. **Sub-delegation** — Agent B narrows scope to `["lab-results:read"]` with
   tighter constraints (maxUses=10, 1-hour expiry, requireMFA=true) and passes
   them to Agent C.
4. **Chain validation** — the full `[root_token, sub_token]` chain is
   cryptographically verified: signatures, scope subset, constraint tightening,
   depth ordering, and parent chain hash.

## Delegation rules enforced

| Property | Root token | Sub-delegation | Rule |
|---|---|---|---|
| maxUses | 100 | 10 | child ≤ parent |
| notAfter | now+24h | now+1h | child ≤ parent |
| requireMFA | false | true | child can only add, never remove |
| scopes | 3 scopes | 1 scope | strict subset |

## Run

```bash
cd sdap-python
PYTHONPATH=src python ../examples/delegation-chain/example.py
```

## Key APIs used

```python
from sdap.delegation import DelegationConstraints, create_delegation_token, decode_delegation_token, validate_delegation_chain
```
