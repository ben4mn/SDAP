"""SDAP audit module — tamper-evident audit log entry creation and chain verification."""

from sdap.audit.chain import create_audit_commitment, verify_audit_chain
from sdap.audit.entries import AuditEntry, create_audit_entry

__all__ = [
    "AuditEntry",
    "create_audit_commitment",
    "create_audit_entry",
    "verify_audit_chain",
]
