"""Certificate validation against a Root CA certificate and optional CRL.

Pure crypto/policy checks — no SQL here. Use ``pki.services.validation`` to
load trust material from SQLite then call these helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class ValidationStatus(str, Enum):
    VALID = "VALID"
    BAD_FORMAT = "BAD_FORMAT"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    UNKNOWN_ISSUER = "UNKNOWN_ISSUER"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class ValidationResult:
    status: ValidationStatus
    message: str
    certificate: x509.Certificate | None = None

    @property
    def ok(self) -> bool:
        return self.status is ValidationStatus.VALID


def _verify_signature(
    certificate: x509.Certificate,
    issuer_public_key: RSAPublicKey,
) -> bool:
    try:
        hash_algo = certificate.signature_hash_algorithm
        if hash_algo is None:
            return False
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_algo,
        )
        return True
    except (InvalidSignature, Exception):
        return False


def validate_certificate(
    certificate: x509.Certificate,
    *,
    root_ca_cert: x509.Certificate,
    crl: x509.CertificateRevocationList | None = None,
    at_time: datetime | None = None,
    check_crl: bool = True,
) -> ValidationResult:
    """Validate a parsed certificate against a trust anchor and optional CRL."""
    if at_time is None:
        at_time = datetime.now(timezone.utc)
    elif at_time.tzinfo is None:
        at_time = at_time.replace(tzinfo=timezone.utc)

    if certificate.issuer != root_ca_cert.subject:
        return ValidationResult(
            status=ValidationStatus.UNKNOWN_ISSUER,
            message=(
                f"Issuer DN does not match trusted Root CA "
                f"(got {certificate.issuer.rfc4514_string()})"
            ),
            certificate=certificate,
        )

    public_key = root_ca_cert.public_key()
    if not isinstance(public_key, RSAPublicKey):
        return ValidationResult(
            status=ValidationStatus.BAD_SIGNATURE,
            message="Root CA public key is not RSA",
            certificate=certificate,
        )
    if not _verify_signature(certificate, public_key):
        return ValidationResult(
            status=ValidationStatus.BAD_SIGNATURE,
            message="Certificate signature does not verify with the Root CA key",
            certificate=certificate,
        )

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if at_time < not_before:
        return ValidationResult(
            status=ValidationStatus.NOT_YET_VALID,
            message=f"Certificate not valid before {not_before.isoformat()}",
            certificate=certificate,
        )
    if at_time > not_after:
        return ValidationResult(
            status=ValidationStatus.EXPIRED,
            message=f"Certificate expired at {not_after.isoformat()}",
            certificate=certificate,
        )

    if check_crl and crl is not None:
        for revoked in crl:
            if revoked.serial_number == certificate.serial_number:
                return ValidationResult(
                    status=ValidationStatus.REVOKED,
                    message=(
                        f"Certificate serial {certificate.serial_number} is listed on the CRL"
                    ),
                    certificate=certificate,
                )

    return ValidationResult(
        status=ValidationStatus.VALID,
        message="Certificate is valid (signature, issuer, dates, CRL)",
        certificate=certificate,
    )
