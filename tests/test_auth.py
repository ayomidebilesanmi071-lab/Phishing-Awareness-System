"""Authentication and role-based access control tests."""

from extensions import db as _db
from models.user import Employee, SecurityAnalyst, User


def test_register_creates_employee(client, app):
    response = client.post(
        "/register",
        data={
            "full_name": "New Hire",
            "email": "newhire@test.local",
            "password": "Password123",
            "confirm_password": "Password123",
        },
    )
    assert response.status_code == 302  # redirect to employee dashboard

    with app.app_context():
        user = User.query.filter_by(email="newhire@test.local").first()
        assert user is not None
        assert isinstance(user, Employee)
        assert user.role == "employee"
        # Plain text must never be stored.
        assert user.password_hash != "Password123"
        assert "Password123" not in user.password_hash
        assert user.check_password("Password123")
        assert not user.check_password("wrong-password")


def test_register_duplicate_email_rejected(client, create_user):
    create_user(role="employee", email="taken@test.local")
    response = client.post(
        "/register",
        data={
            "full_name": "Duplicate",
            "email": "taken@test.local",
            "password": "Password123",
            "confirm_password": "Password123",
        },
    )
    assert response.status_code == 400
    assert b"already exists" in response.data


def test_register_weak_password_rejected(client):
    response = client.post(
        "/register",
        data={
            "full_name": "Weak",
            "email": "weak@test.local",
            "password": "short",
            "confirm_password": "short",
        },
    )
    assert response.status_code == 400
    assert b"at least 8 characters" in response.data


def test_register_password_mismatch_rejected(client):
    response = client.post(
        "/register",
        data={
            "full_name": "Mismatch",
            "email": "mm@test.local",
            "password": "Password123",
            "confirm_password": "Password124",
        },
    )
    assert response.status_code == 400
    assert b"Passwords do not match" in response.data


def test_login_success_redirects_to_role_home(client, create_user, login):
    create_user(role="analyst", email="sam@test.local")
    response = login("sam@test.local")
    assert response.status_code == 302
    assert "/analyst/" in response.headers["Location"]


def test_login_wrong_password(client, create_user, login):
    create_user(role="employee", email="erin@test.local")
    response = client.post(
        "/login",
        data={"email": "erin@test.local", "password": "WrongPass1", "remember": ""},
    )
    assert response.status_code == 200
    assert b"Invalid email or password" in response.data


def test_login_unknown_email(client):
    response = client.post(
        "/login",
        data={"email": "ghost@test.local", "password": "Whatever123", "remember": ""},
    )
    assert response.status_code == 200
    assert b"Invalid email or password" in response.data


def test_deactivated_user_cannot_login(client, create_user):
    create_user(role="employee", email="off@test.local", active=False)
    response = client.post(
        "/login",
        data={"email": "off@test.local", "password": "Password123", "remember": ""},
    )
    assert response.status_code == 200
    assert b"deactivated" in response.data


def test_logout(client, create_user, login):
    create_user(role="employee", email="erin@test.local")
    login("erin@test.local")
    response = client.post("/logout")
    assert response.status_code == 302
    # Session is gone: the dashboard now redirects to login.
    assert client.get("/employee/").status_code == 302


def test_anonymous_redirected_to_login(client):
    response = client.get("/employee/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_employee_cannot_access_analyst_pages(client, create_user, login):
    create_user(role="employee", email="erin@test.local")
    login("erin@test.local")
    assert client.get("/analyst/").status_code == 403
    assert client.get("/analyst/reports").status_code == 403


def test_analyst_cannot_access_admin_pages(client, create_user, login):
    create_user(role="analyst", email="sam@test.local")
    login("sam@test.local")
    assert client.get("/admin/").status_code == 403
    assert client.get("/admin/users").status_code == 403


def test_employee_cannot_access_admin_pages(client, create_user, login):
    create_user(role="employee", email="erin@test.local")
    login("erin@test.local")
    assert client.get("/admin/").status_code == 403


def test_admin_can_access_analyst_dashboard(client, create_user, login):
    create_user(role="admin", email="alice@test.local")
    login("alice@test.local")
    assert client.get("/analyst/").status_code == 200


def test_admin_can_change_user_role(client, create_user, login, app):
    create_user(role="admin", email="alice@test.local")
    analyst_id = create_user(role="analyst", email="sam@test.local")
    login("alice@test.local")

    response = client.post(
        f"/admin/users/{analyst_id}/edit",
        data={"full_name": "Sam", "email": "sam@test.local", "role": "employee", "active": "on"},
    )
    assert response.status_code == 302

    with app.app_context():
        user = _db.session.get(User, analyst_id)
        # The row must now load as the new subclass with the new role.
        assert isinstance(user, Employee)
        assert user.role == "employee"
        assert user.is_active


def test_admin_creates_analyst_account(client, create_user, login, app):
    create_user(role="admin", email="alice@test.local")
    login("alice@test.local")

    response = client.post(
        "/admin/users/new",
        data={
            "full_name": "New Analyst",
            "email": "nana@test.local",
            "password": "Password123",
            "role": "analyst",
        },
    )
    assert response.status_code == 302

    with app.app_context():
        user = User.query.filter_by(email="nana@test.local").first()
        assert isinstance(user, SecurityAnalyst)
        assert user.role == "analyst"


def test_change_password(client, create_user, login, app):
    create_user(role="employee", email="erin@test.local")
    login("erin@test.local")
    response = client.post(
        "/change-password",
        data={
            "current_password": "Password123",
            "new_password": "NewPass4567",
            "confirm_password": "NewPass4567",
        },
    )
    assert response.status_code == 302
    with app.app_context():
        user = User.query.filter_by(email="erin@test.local").first()
        assert user.check_password("NewPass4567")
        assert not user.check_password("Password123")
