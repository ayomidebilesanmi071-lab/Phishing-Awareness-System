"""Application configuration.

All secrets and environment-specific settings are read from environment
variables (or a local `.env` file loaded by python-dotenv in ``app.py``).
Never hard-code production secrets in source code.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Base configuration for the PARS application."""

    # --- Core Flask -------------------------------------------------------
    # In production ALWAYS set SECRET_KEY via the environment.
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change-me-in-production"

    # The database URI. The application factory fills this in with the
    # instance/phishing.db file when it is not provided via the environment.
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or ""
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Secure sessions ---------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True          # JavaScript cannot read the session cookie
    SESSION_COOKIE_SAMESITE = "Lax"         # mitigates CSRF from cross-site requests
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"

    # --- File uploads ------------------------------------------------------
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024    # 2 MB maximum upload size
    ALLOWED_ATTACHMENT_EXTENSIONS = {
        "png", "jpg", "jpeg", "gif", "webp", "pdf", "txt",
    }
    UPLOAD_FOLDER = str(BASE_DIR / "instance" / "uploads")

    # --- CSRF -----------------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600              # CSRF tokens expire after 1 hour
