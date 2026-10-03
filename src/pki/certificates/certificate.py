"""Client certificate helpers: serials, CSR builders, subject names.

CSR-based issuance keeps the private key on the client. The CA only ever
sees a Certificate Signing Request (public key + subject + signature proving
possession of the private key).
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from pki.config import Settings, get_settings


def build_client_name(
    common_name: str,
    *,
    settings: Settings | None = None,
) -> x509.Name:
    """Build an end-entity Distinguished Name (C, O, CN)."""
    settings = settings or get_settings()
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, settings.ca_country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.client_organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def allocate_serial_number() -> int:
    """Allocate a large random certificate serial number."""
    return x509.random_serial_number()


def create_certificate_signing_request(
    private_key: RSAPrivateKey,
    common_name: str,
    *,
    settings: Settings | None = None,
) -> x509.CertificateSigningRequest:
    """Create a CSR signed by the client's private key (proof of possession)."""
    settings = settings or get_settings()
    subject = build_client_name(common_name, settings=settings)
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    return builder.sign(private_key, hashes.SHA256())


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


def load_csr_pem(pem_data: bytes) -> x509.CertificateSigningRequest:
    """Parse a CSR from PEM bytes (e.g. uploaded via the web API)."""
    return x509.load_pem_x509_csr(pem_data)
