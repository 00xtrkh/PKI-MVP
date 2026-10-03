"""Validation service (ORM-backed)."""

from __future__ import annotations

from datetime import datetime

from cryptography import x509

from pki.db.extensions import db
from pki.db.models import Certificate
from pki.services.ca import load_root_ca
from pki.services.revocation import load_crl
from pki.validation.validator import ValidationResult, ValidationStatus, validate_certificate


def validate_certificate_pem(
    certificate_pem: bytes,
    *,
    at_time: datetime | None = None,
    check_crl: bool = True,
) -> ValidationResult:
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
    except Exception as exc:
        return ValidationResult(
            status=ValidationStatus.BAD_FORMAT,
            message=f"Cannot parse certificate PEM: {exc}",
        )

    root = load_root_ca()
    crl = load_crl() if check_crl else None
    return validate_certificate(
        certificate,
        root_ca_cert=root.certificate,
        crl=crl,
        at_time=at_time,
        check_crl=check_crl,
    )


def validate_serial(
    serial: str,
    *,
    at_time: datetime | None = None,
    check_crl: bool = True,
) -> ValidationResult:
    row = db.session.get(Certificate, str(serial))
    if row is None:
        return ValidationResult(
            status=ValidationStatus.BAD_FORMAT,
            message=f"No certificate with serial={serial} in the database",
        )
    return validate_certificate_pem(
        row.certificate_pem,
        at_time=at_time,
        check_crl=check_crl,
    )
