"""PARS - Phishing Awareness & Reporting System.

Application entry point and factory. Run with:

    python app.py                 # development server
    flask --app app run           # or via the Flask CLI
    flask --app app init-db       # create tables
    flask --app app seed-db       # load demo data
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFError
from markupsafe import Markup, escape

# Load environment variables from a local .env file if present.
load_dotenv()

from config import Config  # noqa: E402
from extensions import csrf, db, login_manager  # noqa: E402
from models import User  # noqa: E402,F401  (importing models registers every table)
from models.constants import (  # noqa: E402
    ARTICLE_CATEGORIES,
    ATTACK_TYPES,
    CLASSIFICATIONS,
    SEVERITIES,
    STATUSES,
)


def create_app(config_class=Config, database_uri=None, upload_folder=None):
    """Application factory - builds a fully configured Flask app.

    ``database_uri`` and ``upload_folder`` override the configuration before
    the extensions are initialised (tests use this to point at temporary
    files), because Flask-SQLAlchemy creates its engine during ``init_app``.
    """
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    # Database: default to <instance>/phishing.db unless DATABASE_URL is set.
    if database_uri:
        app.config["SQLALCHEMY_DATABASE_URI"] = database_uri
    elif not app.config.get("SQLALCHEMY_DATABASE_URI"):
        db_path = Path(app.instance_path) / "phishing.db"
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path.as_posix()

    # Uploads live under <instance>/uploads (or the test-supplied folder).
    if upload_folder:
        app.config["UPLOAD_FOLDER"] = upload_folder
    app.config["UPLOAD_FOLDER"] = str(Path(app.config["UPLOAD_FOLDER"]))
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from routes import register_blueprints

    register_blueprints(app)

    # --- Flask-Login configuration --------------------------------------
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "info"
    login_manager.session_protection = "strong"

    _register_template_helpers(app)
    _register_error_handlers(app)
    _register_cli(app)
    return app


def _register_template_helpers(app):
    """Custom filters and globally available constants for templates."""

    @app.template_filter("nl2br")
    def nl2br(value):
        """Render user/admin text safely, converting newlines to <br>.

        The value is escaped first (XSS-safe) and only then are <br> tags
        inserted, so untrusted content can never inject markup.
        """
        if value is None:
            return ""
        return Markup(escape(value).replace("\n", "<br>"))

    # Registered as Jinja globals (not just context) so that they are also
    # visible inside macros imported with `{% from ... import ... %}`.
    app.jinja_env.globals.update(
        ATTACK_TYPES=ATTACK_TYPES,
        STATUSES=STATUSES,
        SEVERITIES=SEVERITIES,
        CLASSIFICATIONS=CLASSIFICATIONS,
        ARTICLE_CATEGORIES=ARTICLE_CATEGORIES,
    )


def _register_error_handlers(app):
    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(_error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    @app.errorhandler(CSRFError)
    def csrf_error(_error):
        flash("Your session expired. Please go back and try again.", "error")
        return redirect(request.referrer or url_for("auth.login"))


def _register_cli(app):
    @app.cli.command("init-db")
    def init_db_command():
        """Create all database tables."""
        db.create_all()
        print("Database initialized at", app.config["SQLALCHEMY_DATABASE_URI"])

    @app.cli.command("seed-db")
    def seed_db_command():
        """Seed the database with demo data (see README for credentials)."""
        from seed import seed

        seed(force=False)


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
