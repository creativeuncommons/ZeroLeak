"""
ZeroLeak Python SDK
===================
Zero-dependency reversible PII & secrets sanitization engine.
"""

from .zeroleak import (
    ZeroLeak,
    SessionVault,
    VaultEntry,
    AuditReceipt,
    mask,
    unmask,
    protect_tool,
    print_audit_receipt,
    luhn_checksum,
    shannon_entropy,
    is_valid_ipv4,
    PATTERNS,
    DEFAULT_ENTITIES,
    DEFAULT_ALLOWLIST,
    __version__,
)

__all__ = [
    "ZeroLeak",
    "SessionVault",
    "VaultEntry",
    "AuditReceipt",
    "mask",
    "unmask",
    "protect_tool",
    "print_audit_receipt",
    "luhn_checksum",
    "shannon_entropy",
    "is_valid_ipv4",
    "PATTERNS",
    "DEFAULT_ENTITIES",
    "DEFAULT_ALLOWLIST",
    "__version__",
]
