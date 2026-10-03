"""CSR submission and certificate issuance (ORM-backed)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pki.ca.key_manager import generate_rsa_private_key
from pki.ca.root_ca import certificate_to_pem
from pki.certificates.certificate import (
    allocate_serial_number,
    create_certificate_signing_request,
    csr_to_pem,
)
from pki.config import Settings, get_settings
from pki.db.extensions import db
from pki.db.models import Certificate, Csr
from pki.services.ca import RootCAMaterial, load_root_ca


@dataclass(frozen=True)
class ClientCsrMaterial:
    private_key: RSAPrivateKey
    csr: x509.CertificateSigningRequest
    csr_id: int
    common_name: str


@dataclass(frozen=True)
class IssuedCertificate:
    certificate: x509.Certificate
    common_name: str
    csr_id: int | None
    serial: str


def create_csr_for_common_name(
    common_name: str,
    *,
    settings: Settings | None = None,
) -> ClientCsrMaterial:
    """Generate client key + CSR; store only the CSR (private key stays in memory)."""
    settings = settings or get_settings()
    private_key = generate_rsa_private_key(settings.client_key_size)
    csr = create_certificate_signing_request(
        private_key, common_name, settings=settings
    )
    row = Csr(common_name=common_name, csr_pem=csr_to_pem(csr), status="pending")
    db.session.add(row)
    db.session.commit()
    return ClientCsrMaterial(
        private_key=private_key,
        csr=csr,
        csr_id=row.id,
        common_name=common_name,
    )


def submit_csr_pem(csr_pem: bytes) -> int:
    """Accept an uploaded CSR PEM. Returns the new CSR id."""
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise ValueError("CSR subject must include a Common Name (CN)")
    common_name = str(cn_attrs[0].value)
    row = Csr(common_name=common_name, csr_pem=csr_pem, status="pending")
    db.session.add(row)
    db.session.commit()
    return row.id


def list_csrs(*, status: str | None = None) -> list[Csr]:
    q = db.select(Csr).order_by(Csr.id.desc())
    if status is not None:
        q = q.where(Csr.status == status)
    return list(db.session.scalars(q))


def list_certificates(*, include_revoked: bool = True) -> list[Certificate]:
    q = db.select(Certificate).order_by(Certificate.created_at.desc())
    if not include_revoked:
        q = q.where(Certificate.revoked_at.is_(None))
    return list(db.session.scalars(q))


def get_certificate_by_serial(serial: str) -> Certificate | None:
    return db.session.get(Certificate, str(serial))


def issue_certificate(
    *,
    csr_id: int | None = None,
    csr: x509.CertificateSigningRequest | None = None,
    root_ca: RootCAMaterial | None = None,
    serial_number: int | None = None,
    not_before: datetime | None = None,
    force: bool = False,
    settings: Settings | None = None,
) -> IssuedCertificate:
    settings = settings or get_settings()
    root_ca = root_ca or load_root_ca()

    resolved_csr_id = csr_id
    csr_row: Csr | None = None
    if csr is None:
        if csr_id is None:
            raise ValueError("Provide csr_id or csr")
        csr_row = db.session.get(Csr, csr_id)
        if csr_row is None:
            raise FileNotFoundError(f"CSR id={csr_id} not found")
        csr = x509.load_pem_x509_csr(csr_row.csr_pem)
    elif csr_id is None:
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = str(cn_attrs[0].value) if cn_attrs else "unknown"
        csr_row = Csr(common_name=common_name, csr_pem=csr_to_pem(csr), status="pending")
        db.session.add(csr_row)
        db.session.flush()
        resolved_csr_id = csr_row.id

    if not csr.is_signature_valid:
        raise ValueError(
            "CSR signature is invalid — the requester may not own the private key"
        )

    subject = csr.subject
    cn_attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise ValueError("CSR subject must include a Common Name (CN)")
    common_name = str(cn_attrs[0].value)

    existing = db.session.scalar(
        db.select(Certificate)
        .where(Certificate.common_name == common_name)
        .where(Certificate.revoked_at.is_(None))
        .order_by(Certificate.created_at.desc())
    )
    if existing is not None and not force:
        raise FileExistsError(
            f"Active certificate already exists for CN={common_name!r}. "
            "Pass force=True to replace."
        )

    if not_before is None:
        not_before = datetime.now(timezone.utc)
    elif not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)

    not_after = not_before + timedelta(days=settings.client_validity_days)
    if serial_number is None:
        serial_number = allocate_serial_number()

    public_key = csr.public_key()
    ca_public_key = root_ca.certificate.public_key()
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_ca.certificate.subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(private_key=root_ca.private_key, algorithm=hashes.SHA256())
    )

    serial_str = str(certificate.serial_number)
    cert_row = db.session.get(Certificate, serial_str)
    if cert_row is None:
        cert_row = Certificate(serial=serial_str)
        db.session.add(cert_row)

    cert_row.common_name = common_name
    cert_row.subject_dn = certificate.subject.rfc4514_string()
    cert_row.certificate_pem = certificate_to_pem(certificate)
    cert_row.not_before = certificate.not_valid_before_utc
    cert_row.not_after = certificate.not_valid_after_utc
    cert_row.csr_id = resolved_csr_id
    cert_row.revoked_at = None

    if resolved_csr_id is not None:
        csr_row = csr_row or db.session.get(Csr, resolved_csr_id)
        if csr_row is not None:
            csr_row.status = "issued"
            csr_row.issued_serial = serial_str

    db.session.commit()

    return IssuedCertificate(
        certificate=certificate,
        common_name=common_name,
        csr_id=resolved_csr_id,
        serial=serial_str,
    )
