"""Authentication routes.

Passwords are hashed with Werkzeug (PBKDF2) before storage, sessions are
managed by Flask-Login, and every POST is protected by CSRF tokens.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from extensions import db
from models.user import User
from routes import home_for
from services.audit_service import AuditService
from services.user_service import UserService, UserValidationError

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for(home_for(current_user)))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()

        if user is not None and user.check_password(password):
            if not user.is_active:
                flash("This account has been deactivated. Contact an administrator.", "error")
                return render_template("auth/login.html", email=email)
            login_user(user, remember=bool(request.form.get("remember")))
            AuditService.log_action(user, "login", f"{user.full_name} logged in.")
            db.session.commit()

            next_url = request.args.get("next")
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for(home_for(user)))

        flash("Invalid email or password.", "error")

    return render_template("auth/login.html", email=request.form.get("email", ""))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for(home_for(current_user)))

    if request.method == "POST":
        try:
            user = UserService.register(
                request.form.get("full_name", ""),
                request.form.get("email", ""),
                request.form.get("password", ""),
                request.form.get("confirm_password", ""),
            )
        except UserValidationError as exc:
            return (
                render_template(
                    "auth/register.html",
                    form_data=request.form,
                    form_errors=exc.errors,
                ),
                400,
            )
        AuditService.log_action(user, "account_registered",
                                f"{user.full_name} registered a new employee account.")
        db.session.commit()
        login_user(user)
        flash("Welcome to PARS! Your employee account has been created.", "success")
        return redirect(url_for(home_for(user)))

    return render_template("auth/register.html", form_data={}, form_errors={})


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    name = current_user.full_name
    logout_user()
    flash(f"{name} logged out. Stay alert out there!", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        errors = {}
        if not current_user.check_password(current_pw):
            errors["current_password"] = "Current password is incorrect."
        errors.update(UserService.validate_password(new_pw, confirm))
        if current_pw and new_pw and current_pw == new_pw:
            errors["new_password"] = "The new password must differ from the current one."

        if errors:
            return render_template("auth/change_password.html", form_errors=errors), 400

        current_user.set_password(new_pw)
        AuditService.log_action(current_user, "password_change",
                                f"{current_user.full_name} changed their password.")
        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for(home_for(current_user)))

    return render_template("auth/change_password.html", form_errors={})
