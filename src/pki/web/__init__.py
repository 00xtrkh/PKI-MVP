"""Flask application factory for MiniPKI."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask

from pki.config import get_settings
from pki.db.extensions import db
from pki.services.ca import ensure_root_ca
from pki.services.revocation import ensure_empty_crl

_WEB_DIR = Path(__file__).resolve().parent


def create_app(config: dict | None = None) -> Flask:
    """Create the Flask app, init ORM, and ensure a Root CA exists."""
    settings = get_settings()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)

    app = Flask(
        __name__,
        template_folder=str(_WEB_DIR / "templates"),
        static_folder=str(_WEB_DIR / "static"),
    )
    app.config["SECRET_KEY"] = os.getenv(
        "MINIPKI_FLASK_SECRET", "minipki-dev-secret-change-me"
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{settings.database_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if config:
        app.config.update(config)

    # Register models on metadata before create_all.
    import pki.db.models  # noqa: F401

    db.init_app(app)

    from pki.web.api import api_bp
    from pki.web.ui import ui_bp

    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.context_processor
    def _inject_auth():
        from pki.web.auth import is_admin

        return {"is_admin": is_admin()}

    with app.app_context():
        db.create_all()
        # Generate Root CA + empty CRL on first run if missing.
        ensure_root_ca()
        ensure_empty_crl()

    return app
