"""Certificate revocation and CRL handling (re-exports SQLite-backed services)."""

from pki.services.revocation import (
    CrlMaterial,
    RevocationEntry,
    ensure_empty_crl,
    is_revoked,
    list_revoked,
    load_crl,
    revoke_by_cn,
    revoke_serial,
)

__all__ = [
    "CrlMaterial",
    "RevocationEntry",
    "ensure_empty_crl",
    "is_revoked",
    "list_revoked",
    "load_crl",
    "revoke_by_cn",
    "revoke_serial",
]
