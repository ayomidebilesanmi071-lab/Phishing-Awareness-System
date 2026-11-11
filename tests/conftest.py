"""Shared pytest fixtures.

Fixtures deliberately return plain ids (not ORM instances) so tests never
touch detached instances outside an application context.
"""

from datetime import date

import pytest

from app import create_app
from config import Config
from extensions import db as _db


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_DATABASE_URI = ""


@pytest.fixture()
def app(tmp_path):
    # The URI and upload folder must be supplied to create_app (not set
    # afterwards) because Flask-SQLAlchemy creates its engine in init_app.
    application = create_app(
        TestConfig,
        database_uri="sqlite:///" + (tmp_path / "test.db").as_posix(),
        upload_folder=str(tmp_path / "uploads"),
    )

    with application.app_context():
        _db.create_all()

    yield application

    with application.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def create_user(app):
    """Create a user of the given role; returns the user id."""

    def _create(role="employee", email=None, name=None, password="Password123", active=True):
        from models.user import Administrator, Employee, SecurityAnalyst

        user_class = {"employee": Employee, "analyst": SecurityAnalyst, "admin": Administrator}[role]
        with app.app_context():
            user = user_class(
                full_name=name or f"{role.title()} User",
                email=email or f"{role.lower()}@test.local",
            )
            user.set_password(password)
            user.active = active
            _db.session.add(user)
            _db.session.commit()
            return user.id

    return _create


@pytest.fixture()
def get_user(app):
    """Fetch a fresh user instance inside an application context."""

    def _get(user_id):
        from models.user import User

        with app.app_context():
            return _db.session.get(User, user_id)

    return _get


@pytest.fixture()
def login(client):
    def _login(email, password="Password123"):
        return client.post(
            "/login",
            data={"email": email, "password": password, "remember": ""},
            follow_redirects=False,
        )

    return _login


@pytest.fixture()
def make_report(app, create_user):
    """Create a phishing report; returns the report id."""

    def _make(reporter_id=None, **overrides):
        from models.report import PhishingReport

        if reporter_id is None:
            reporter_id = create_user(role="employee", email="reporter@test.local")
        data = {
            "sender_address": "attacker@evil.example",
            "subject": "Verify your account now",
            "suspicious_link": "https://evil.example/login",
            "message_content": "Your mailbox will be suspended. Please verify your password.",
            "attack_type": "phishing",
            "severity": "low",
            "status": "pending",
            "date_received": date(2025, 1, 1),
            "comments": None,
        }
        data.update(overrides)
        with app.app_context():
            report = PhishingReport(reporter_id=reporter_id, **data)
            _db.session.add(report)
            _db.session.commit()
            return report.id

    return _make


@pytest.fixture()
def get_report(app):
    """Fetch a fresh report instance inside an application context."""

    def _get(report_id):
        from models.report import PhishingReport

        with app.app_context():
            return _db.session.get(PhishingReport, report_id)

    return _get
