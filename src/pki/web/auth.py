"""Admin authentication for privileged MiniPKI operations.

Public: view Root CA, upload CSR, list certs, validate, CRL.
Admin only: issue certificates, revoke certificates.
"""

from __future__ import annotations

import secrets
from functools import wraps

from flask import (
    flash,
    jsonify,
    redirect,
    request,
    session,
    url_for,
)

from pki.config import get_settings

SESSION_KEY = "is_admin"
ADMIN_USERNAME = "admin"


def admin_password_configured() -> bool:
    return bool(get_settings().admin_password)


def verify_admin_password(password: str) -> bool:
    expected = get_settings().admin_password
    if not expected or not password:
        return False
    return secrets.compare_digest(password, expected)


def is_admin() -> bool:
    return bool(session.get(SESSION_KEY))


def login_admin() -> None:
    session[SESSION_KEY] = True
    session.permanent = True


def logout_admin() -> None:
    session.pop(SESSION_KEY, None)


def _unauthorized_api():
    return (
        jsonify({"error": "admin authentication required"}),
        401,
        {"WWW-Authenticate": 'Basic realm="MiniPKI Admin"'},
    )


def _check_basic_auth() -> bool:
    auth = request.authorization
    if auth is None:
        return False
    if auth.username != ADMIN_USERNAME:
        return False
    return verify_admin_password(auth.password or "")


def require_admin_ui(view):
    """Redirect anonymous users to the login page for UI routes."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if is_admin():
            return view(*args, **kwargs)
        flash("Admin login required for this action.", "error")
        return redirect(url_for("ui.login", next=request.path))

    return wrapped


def require_admin_api(view):
    """Require HTTP Basic auth (user ``admin``) for JSON API routes."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if is_admin() or _check_basic_auth():
            return view(*args, **kwargs)
        return _unauthorized_api()

    return wrapped
