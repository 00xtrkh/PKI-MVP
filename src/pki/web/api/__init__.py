"""JSON API blueprint."""

from flask import Blueprint

api_bp = Blueprint("api", __name__)

from pki.web.api import routes as _routes  # noqa: E402, F401
