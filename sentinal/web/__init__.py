from __future__ import annotations

from flask import Flask


def create_app() -> Flask:
    from ..config import get_settings

    settings = get_settings()
    app = Flask(__name__)
    app.config["SECRET_KEY"] = settings.flask_secret_key

    from .routes import bp

    app.register_blueprint(bp)
    return app
