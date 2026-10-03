"""Revocation / CRL service (ORM-backed)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from pki.config import Settings, get_settings
from pki.db.extensions import db
from pki.db.models import Certificate, Crl
from pki.services.ca import RootCAMaterial, load_root_ca


@dataclass(frozen=True)
class RevocationEntry:
    serial_number: int
    revocation_date: datetime


@dataclass(frozen=True)
class CrlMaterial:
    crl: x509.CertificateRevocationList
    revoked: tuple[RevocationEntry, ...]


def _entries_from_crl(crl: x509.CertificateRevocationList) -> list[RevocationEntry]:
    entries: list[RevocationEntry] = []
    for revoked in crl:
        rev_date = getattr(revoked, "revocation_date_utc", None) or revoked.revocation_date
        if rev_date.tzinfo is None:
            rev_date = rev_date.replace(tzinfo=timezone.utc)
        entries.append(
            RevocationEntry(serial_number=revoked.serial_number, revocation_date=rev_date)
        )
    return entries


def _build_crl(
    *,
    root_ca: RootCAMaterial,
    entries: list[RevocationEntry],
    last_update: datetime,
    next_update: datetime,
) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_ca.certificate.subject)
        .last_update(last_update)
        .next_update(next_update)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_ca.certificate.public_key()
            ),
            critical=False,
        )
    )
    for entry in entries:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(entry.serial_number)
            .revocation_date(entry.revocation_date)
            .build()
        )
    return builder.sign(private_key=root_ca.private_key, algorithm=hashes.SHA256())


def load_crl() -> x509.CertificateRevocationList | None:
    row = db.session.get(Crl, 1)
    if row is None:
        return None
    return x509.load_pem_x509_crl(row.crl_pem)


def list_revoked() -> list[RevocationEntry]:
    crl = load_crl()
    if crl is None:
        return []
    return _entries_from_crl(crl)


def is_revoked(serial_number: int) -> bool:
    return any(e.serial_number == serial_number for e in list_revoked())


def ensure_empty_crl(
    *,
    root_ca: RootCAMaterial | None = None,
    force: bool = False,
    settings: Settings | None = None,
) -> CrlMaterial:
    settings = settings or get_settings()
    root_ca = root_ca or load_root_ca()

    existing = load_crl()
    if existing is not None and not force:
        return CrlMaterial(crl=existing, revoked=tuple(_entries_from_crl(existing)))

    last_update = datetime.now(timezone.utc)
    next_update = last_update + timedelta(days=settings.crl_next_update_days)
    crl = _build_crl(
        root_ca=root_ca,
        entries=[],
        last_update=last_update,
        next_update=next_update,
    )
    _save_crl_row(crl, last_update, next_update)
    return CrlMaterial(crl=crl, revoked=())


def _save_crl_row(
    crl: x509.CertificateRevocationList,
    last_update: datetime,
    next_update: datetime,
) -> None:
    row = db.session.get(Crl, 1)
    if row is None:
        row = Crl(id=1)
        db.session.add(row)
    row.crl_pem = crl.public_bytes(serialization.Encoding.PEM)
    row.last_update = last_update
    row.next_update = next_update
    row.updated_at = datetime.now(timezone.utc)
    db.session.commit()


def revoke_serial(
    serial_number: int,
    *,
    root_ca: RootCAMaterial | None = None,
    revocation_date: datetime | None = None,
    settings: Settings | None = None,
) -> CrlMaterial:
    settings = settings or get_settings()
    root_ca = root_ca or load_root_ca()

    if revocation_date is None:
        revocation_date = datetime.now(timezone.utc)
    elif revocation_date.tzinfo is None:
        revocation_date = revocation_date.replace(tzinfo=timezone.utc)

    existing = list_revoked()
    if any(e.serial_number == serial_number for e in existing):
        crl = load_crl()
        assert crl is not None
        return CrlMaterial(crl=crl, revoked=tuple(existing))

    entries = existing + [
        RevocationEntry(serial_number=serial_number, revocation_date=revocation_date)
    ]
    last_update = datetime.now(timezone.utc)
    next_update = last_update + timedelta(days=settings.crl_next_update_days)
    crl = _build_crl(
        root_ca=root_ca,
        entries=entries,
        last_update=last_update,
        next_update=next_update,
    )
    _save_crl_row(crl, last_update, next_update)

    cert_row = db.session.get(Certificate, str(serial_number))
    if cert_row is not None:
        cert_row.revoked_at = revocation_date
        db.session.commit()

    return CrlMaterial(crl=crl, revoked=tuple(entries))


def revoke_by_cn(
    common_name: str,
    *,
    root_ca: RootCAMaterial | None = None,
    settings: Settings | None = None,
) -> tuple[CrlMaterial, x509.Certificate]:
    row = db.session.scalar(
        db.select(Certificate)
        .where(Certificate.common_name == common_name)
        .order_by(Certificate.created_at.desc())
    )
    if row is None:
        raise FileNotFoundError(f"No certificate found for CN={common_name!r}")
    certificate = x509.load_pem_x509_certificate(row.certificate_pem)
    material = revoke_serial(
        certificate.serial_number,
        root_ca=root_ca,
        settings=settings,
    )
    return material, certificate
