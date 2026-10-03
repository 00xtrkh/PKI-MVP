"""SQLAlchemy ORM models for MiniPKI persistence."""

from __future__ import annotations

from datetime import datetime, timezone

from pki.db.extensions import db


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RootCa(db.Model):
    """Singleton Root CA row (id must stay 1)."""

    __tablename__ = "root_ca"

    id = db.Column(db.Integer, primary_key=True)
    private_key_pem = db.Column(db.LargeBinary, nullable=False)
    certificate_pem = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)


class Csr(db.Model):
    __tablename__ = "csrs"

    id = db.Column(db.Integer, primary_key=True)
    common_name = db.Column(db.String(255), nullable=False, index=True)
    csr_pem = db.Column(db.LargeBinary, nullable=False)
    status = db.Column(db.String(32), nullable=False, default="pending")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    issued_serial = db.Column(db.String(128), nullable=True)


class Certificate(db.Model):
    __tablename__ = "certificates"

    serial = db.Column(db.String(128), primary_key=True)
    common_name = db.Column(db.String(255), nullable=False, index=True)
    subject_dn = db.Column(db.String(512), nullable=False)
    certificate_pem = db.Column(db.LargeBinary, nullable=False)
    not_before = db.Column(db.DateTime(timezone=True), nullable=False)
    not_after = db.Column(db.DateTime(timezone=True), nullable=False)
    csr_id = db.Column(db.Integer, db.ForeignKey("csrs.id"), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    csr = db.relationship("Csr", backref=db.backref("certificates", lazy=True))

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class Crl(db.Model):
    """Singleton current CRL (id must stay 1)."""

    __tablename__ = "crl"

    id = db.Column(db.Integer, primary_key=True)
    crl_pem = db.Column(db.LargeBinary, nullable=False)
    last_update = db.Column(db.DateTime(timezone=True), nullable=False)
    next_update = db.Column(db.DateTime(timezone=True), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
