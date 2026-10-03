"""HTML UI blueprint (Jinja templates)."""

from flask import Blueprint

ui_bp = Blueprint("ui", __name__)

from pki.web.ui import routes as _routes  # noqa: E402, F401
