"""Root CA crypto: self-signed X.509 trust anchor builders.

Persistence lives in ``pki.db`` / ``pki.services.ca`` — this module only builds
and serializes certificates.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from pki.config import Settings, get_settings


def build_ca_name(settings: Settings | None = None) -> x509.Name:
    """Build the Root CA Distinguished Name from config (C, O, CN)."""
    settings = settings or get_settings()
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, settings.ca_country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.ca_organization),
            x509.NameAttribute(NameOID.COMMON_NAME, settings.ca_common_name),
        ]
    )


def create_self_signed_root_certificate(
    private_key: RSAPrivateKey,
    *,
    settings: Settings | None = None,
    not_before: datetime | None = None,
) -> x509.Certificate:
    """Create a self-signed X.509 v3 Root CA certificate.

    Subject and Issuer are identical. The cert is signed with ``private_key``
    using SHA-256.
    """
    settings = settings or get_settings()
    name = build_ca_name(settings)

    if not_before is None:
        not_before = datetime.now(timezone.utc)
    elif not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)

    not_after = not_before + timedelta(days=settings.ca_validity_days)
    public_key = private_key.public_key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        ),
        critical=False,
    )

    return builder.sign(private_key=private_key, algorithm=hashes.SHA256())


def certificate_to_pem(certificate: x509.Certificate) -> bytes:
    """Serialize a certificate to PEM (public; not encrypted)."""
    return certificate.public_bytes(serialization.Encoding.PEM)


def load_certificate_pem(pem_data: bytes) -> x509.Certificate:
    """Parse an X.509 certificate from PEM bytes."""
    return x509.load_pem_x509_certificate(pem_data)


def load_certificate(path: str | Path) -> x509.Certificate:
    """Load an X.509 certificate from a PEM file (utility / tests)."""
    return load_certificate_pem(Path(path).read_bytes())
