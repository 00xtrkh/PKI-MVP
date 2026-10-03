"""JSON API for MiniPKI core operations.

Public: health, root-ca, list/upload CSRs, list certs, CRL, validate.
Admin (HTTP Basic user ``admin``): issue, revoke.
"""

from __future__ import annotations

from flask import jsonify, request

from pki.ca.root_ca import certificate_to_pem
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
from pki.web.api import api_bp
from pki.web.auth import require_admin_api


@api_bp.get("/health")
def health():
    return jsonify({"status": "ok"})


@api_bp.get("/root-ca")
def api_root_ca():
    root = load_root_ca()
    cert = root.certificate
    return jsonify(
        {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": str(cert.serial_number),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "pem": certificate_to_pem(cert).decode("ascii"),
        }
    )


@api_bp.get("/csrs")
def api_list_csrs():
    status = request.args.get("status")
    rows = list_csrs(status=status)
    return jsonify(
        [
            {
                "id": r.id,
                "common_name": r.common_name,
                "status": r.status,
                "issued_serial": r.issued_serial,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    )


@api_bp.post("/csrs")
def api_upload_csr():
    """Accept a client-generated CSR PEM (body or JSON ``{"pem": "..."}``).

    The CA never generates or receives the client's private key.
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
        pem_text = data.get("pem") or data.get("csr_pem") or ""
        pem = pem_text.encode("utf-8") if isinstance(pem_text, str) else bytes(pem_text)
    else:
        pem = request.get_data()

    if not isinstance(pem, (bytes, bytearray)) or not bytes(pem).strip():
        return jsonify(
            {
                "error": "CSR PEM required. Generate it locally with OpenSSL; "
                "do not send your private key."
            }
        ), 400
    try:
        csr_id = submit_csr_pem(bytes(pem))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"csr_id": csr_id}), 201


@api_bp.post("/certificates/issue")
@require_admin_api
def api_issue():
    data = request.get_json(silent=True) or {}
    csr_id = data.get("csr_id")
    if csr_id is None:
        return jsonify({"error": "csr_id required"}), 400
    try:
        issued = issue_certificate(csr_id=int(csr_id), force=bool(data.get("force")))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(
        {
            "serial": issued.serial,
            "common_name": issued.common_name,
            "pem": certificate_to_pem(issued.certificate).decode("ascii"),
        }
    ), 201


@api_bp.get("/certificates")
def api_list_certificates():
    rows = list_certificates()
    return jsonify(
        [
            {
                "serial": r.serial,
                "common_name": r.common_name,
                "subject_dn": r.subject_dn,
                "not_before": r.not_before.isoformat() if r.not_before else None,
                "not_after": r.not_after.isoformat() if r.not_after else None,
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            }
            for r in rows
        ]
    )


@api_bp.get("/certificates/<serial>")
def api_get_certificate(serial: str):
    row = get_certificate_by_serial(serial)
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(
        {
            "serial": row.serial,
            "common_name": row.common_name,
            "pem": row.certificate_pem.decode("ascii"),
            "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        }
    )


@api_bp.post("/revoke")
@require_admin_api
def api_revoke():
    data = request.get_json(silent=True) or {}
    try:
        if data.get("common_name"):
            material, cert = revoke_by_cn(data["common_name"])
            serial = cert.serial_number
        elif data.get("serial") is not None:
            serial = int(data["serial"])
            material = revoke_serial(serial)
        else:
            return jsonify({"error": "common_name or serial required"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(
        {
            "serial": str(serial),
            "revoked_count": len(material.revoked),
        }
    )


@api_bp.get("/crl")
def api_crl():
    return jsonify(
        [
            {
                "serial": str(e.serial_number),
                "revocation_date": e.revocation_date.isoformat(),
            }
            for e in list_revoked()
        ]
    )


@api_bp.post("/validate")
def api_validate():
    data = request.get_json(silent=True) or {}
    try:
        if data.get("serial"):
            result = validate_serial(str(data["serial"]))
        elif data.get("pem"):
            result = validate_certificate_pem(data["pem"].encode("utf-8"))
        else:
            return jsonify({"error": "serial or pem required"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"status": result.status.value, "message": result.message})
