"""Root CA service (ORM-backed)."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from pki.ca.key_manager import (
    generate_rsa_private_key,
    load_private_key_pem,
    private_key_to_pem,
)
from pki.ca.root_ca import certificate_to_pem, create_self_signed_root_certificate
from pki.config import Settings, get_settings
from pki.db.extensions import db
from pki.db.models import RootCa


@dataclass(frozen=True)
class RootCAMaterial:
    private_key: RSAPrivateKey
    certificate: x509.Certificate


def root_ca_exists() -> bool:
    return db.session.get(RootCa, 1) is not None


def initialize_root_ca(
    *,
    force: bool = False,
    passphrase: bytes | str | None = None,
    settings: Settings | None = None,
) -> RootCAMaterial:
    """Create a Root CA and store encrypted key + cert PEM via the ORM."""
    settings = settings or get_settings()
    existing = db.session.get(RootCa, 1)
    if existing is not None and not force:
        raise FileExistsError(
            "Root CA already exists in the database. Pass force=True to overwrite."
        )

    private_key = generate_rsa_private_key(settings.ca_key_size)
    certificate = create_self_signed_root_certificate(private_key, settings=settings)

    if existing is None:
        existing = RootCa(id=1)
        db.session.add(existing)

    existing.private_key_pem = private_key_to_pem(private_key, passphrase=passphrase)
    existing.certificate_pem = certificate_to_pem(certificate)
    db.session.commit()

    return RootCAMaterial(private_key=private_key, certificate=certificate)


def ensure_root_ca(
    *,
    settings: Settings | None = None,
) -> RootCAMaterial:
    """Load Root CA if present, otherwise generate and store one."""
    if root_ca_exists():
        return load_root_ca()
    return initialize_root_ca(force=False, settings=settings)


def load_root_ca(
    *,
    passphrase: bytes | str | None = None,
) -> RootCAMaterial:
    row = db.session.get(RootCa, 1)
    if row is None:
        raise FileNotFoundError(
            "Root CA not found in the database. It should be created on app startup."
        )
    private_key = load_private_key_pem(row.private_key_pem, passphrase=passphrase)
    certificate = x509.load_pem_x509_certificate(row.certificate_pem)
    return RootCAMaterial(private_key=private_key, certificate=certificate)
