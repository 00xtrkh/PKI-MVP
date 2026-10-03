"""UI routes for core MiniPKI features."""

from __future__ import annotations

from flask import flash, redirect, render_template, request, url_for

from pki.ca.root_ca import certificate_to_pem
from pki.config import get_settings
from pki.services import (
    get_certificate_by_serial,
    issue_certificate,
    list_certificates,
    list_csrs,
    list_revoked,
    load_root_ca,
    revoke_by_cn,
    revoke_serial,
    submit_csr_pem,
    validate_certificate_pem,
    validate_serial,
)
from pki.web.auth import is_admin, login_admin, logout_admin, verify_admin_password
from pki.web.ui import ui_bp


@ui_bp.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next") or request.form.get("next") or url_for("ui.index")
    if request.method == "POST":
        password = request.form.get("password") or ""
        if verify_admin_password(password):
            login_admin()
            flash("Logged in as admin.", "success")
            return redirect(next_url)
        flash("Invalid admin password.", "error")
    return render_template("login.html", next_url=next_url)


@ui_bp.post("/logout")
def logout():
    logout_admin()
    flash("Logged out.", "success")
    return redirect(url_for("ui.index"))


@ui_bp.get("/")
def index():
    root = load_root_ca()
    certs = list_certificates()
    pending = list_csrs(status="pending")
    revoked = list_revoked()
    return render_template(
        "index.html",
        root=root,
        cert_count=len(certs),
        pending_count=len(pending),
        revoked_count=len(revoked),
    )


@ui_bp.get("/root-ca")
def root_ca_page():
    root = load_root_ca()
    cert = root.certificate
    pem = certificate_to_pem(cert).decode("ascii")
    return render_template(
        "root_ca.html",
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=cert.serial_number,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        pem=pem,
    )


@ui_bp.route("/csrs", methods=["GET", "POST"])
def csrs_page():
    if request.method == "POST":
        action = request.form.get("action", "upload")
        try:
            if action == "upload":
                uploaded = request.files.get("csr_file")
                raw = request.form.get("csr_pem", "").encode("utf-8")
                if uploaded and uploaded.filename:
                    raw = uploaded.read()
                if not raw.strip():
                    raise ValueError("Provide a CSR PEM file or paste PEM text")
                csr_id = submit_csr_pem(raw)
                flash(f"CSR uploaded as id={csr_id}", "success")
            elif action == "issue":
                if not is_admin():
                    flash("Admin login required to issue certificates.", "error")
                    return redirect(url_for("ui.login", next=url_for("ui.csrs_page")))
                csr_id = int(request.form["csr_id"])
                force = request.form.get("force") == "on"
                issued = issue_certificate(csr_id=csr_id, force=force)
                flash(
                    f"Issued certificate for {issued.common_name} "
                    f"(serial {issued.serial})",
                    "success",
                )
            else:
                raise ValueError("Unknown action")
        except Exception as exc:
            flash(str(exc), "error")

    settings = get_settings()
    return render_template(
        "csrs.html",
        csrs=list_csrs(),
        ca_country=settings.ca_country,
        client_organization=settings.client_organization,
        client_key_size=settings.client_key_size,
    )


@ui_bp.route("/certificates", methods=["GET", "POST"])
def certificates_page():
    if request.method == "POST":
        if not is_admin():
            flash("Admin login required to revoke certificates.", "error")
            return redirect(url_for("ui.login", next=url_for("ui.certificates_page")))
        try:
            action = request.form.get("action")
            if action == "revoke_cn":
                cn = (request.form.get("common_name") or "").strip()
                revoke_by_cn(cn)
                flash(f"Revoked certificate for CN={cn}", "success")
            elif action == "revoke_serial":
                serial = int((request.form.get("serial") or "").strip())
                revoke_serial(serial)
                flash(f"Revoked serial {serial}", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return redirect(url_for("ui.certificates_page"))

    return render_template(
        "certificates.html",
        certificates=list_certificates(),
    )


@ui_bp.get("/certificates/<serial>/pem")
def certificate_pem(serial: str):
    row = get_certificate_by_serial(serial)
    if row is None:
        flash("Certificate not found", "error")
        return redirect(url_for("ui.certificates_page"))
    return (
        row.certificate_pem.decode("ascii"),
        200,
        {
            "Content-Type": "application/x-pem-file",
            "Content-Disposition": f'attachment; filename="{row.common_name}.crt"',
        },
    )


@ui_bp.route("/validate", methods=["GET", "POST"])
def validate_page():
    result = None
    if request.method == "POST":
        try:
            serial = (request.form.get("serial") or "").strip()
            pem_text = (request.form.get("pem") or "").strip()
            uploaded = request.files.get("pem_file")
            if serial:
                result = validate_serial(serial)
            else:
                raw = pem_text.encode("utf-8")
                if uploaded and uploaded.filename:
                    raw = uploaded.read()
                if not raw.strip():
                    raise ValueError("Provide a serial or certificate PEM")
                result = validate_certificate_pem(raw)
        except Exception as exc:
            flash(str(exc), "error")

    return render_template("validate.html", result=result)


@ui_bp.get("/crl")
def crl_page():
    return render_template("crl.html", entries=list_revoked())
