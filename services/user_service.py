"""User service - registration and administrator user management.

Registration always creates Employee accounts. Administrators can create
accounts for any role, change roles, activate/deactivate accounts, reset
passwords and delete accounts that have no dependent records.
"""

import re

from sqlalchemy import update

from extensions import db
from models.constants import ROLE_LABELS, ROLES
from models.investigation import Investigation
from models.report import AuditLog, PhishingReport
from models.user import Employee, User
from services.audit_service import AuditService

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UserValidationError(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("User validation failed")


class UserService:
    """Business logic for accounts."""

    MIN_PASSWORD_LENGTH = 8

    # ------------------------------------------------------------------ #
    @staticmethod
    def validate_password(password, confirm=None):
        errors = {}
        if not password:
            errors["password"] = "Password is required."
        elif len(password) < UserService.MIN_PASSWORD_LENGTH:
            errors["password"] = (
                f"Password must be at least {UserService.MIN_PASSWORD_LENGTH} characters."
            )
        elif not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            errors["password"] = "Password must contain at least one letter and one number."
        if confirm is not None and password != confirm:
            errors["confirm_password"] = "Passwords do not match."
        return errors

    @staticmethod
    def validate_registration(full_name, email, password, confirm):
        errors = {}
        full_name = (full_name or "").strip()
        email = (email or "").strip().lower()

        if not full_name:
            errors["full_name"] = "Full name is required."
        elif len(full_name) > 120:
            errors["full_name"] = "Name must be 120 characters or fewer."

        if not EMAIL_RE.fullmatch(email):
            errors["email"] = "Enter a valid email address."
        elif User.query.filter_by(email=email).first() is not None:
            errors["email"] = "An account with this email already exists."

        errors.update(UserService.validate_password(password, confirm))
        if errors:
            raise UserValidationError(errors)
        return {"full_name": full_name, "email": email}

    @staticmethod
    def register(full_name, email, password, confirm):
        """Self-registration - always creates an Employee account."""
        cleaned = UserService.validate_registration(full_name, email, password, confirm)
        user = Employee(full_name=cleaned["full_name"], email=cleaned["email"])
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    # ------------------------------------------------------------------ #
    # Administrator operations
    # ------------------------------------------------------------------ #
    @staticmethod
    def create_user(actor, full_name, email, password, role):
        """Create an account for any role (actor must be an Administrator)."""
        errors = {}
        full_name = (full_name or "").strip()
        email = (email or "").strip().lower()

        if not full_name or len(full_name) > 120:
            errors["full_name"] = "Enter a valid full name."
        if not EMAIL_RE.fullmatch(email):
            errors["email"] = "Enter a valid email address."
        elif User.query.filter_by(email=email).first() is not None:
            errors["email"] = "An account with this email already exists."
        if role not in ROLES:
            errors["role"] = "Select a valid role."
        errors.update(UserService.validate_password(password))

        if errors:
            raise UserValidationError(errors)

        user = actor.create_user(full_name, email, password, role)
        db.session.flush()
        AuditService.log_action(
            actor,
            "user_created",
            f"{actor.full_name} created a {ROLE_LABELS[role]} account for {email}.",
        )
        db.session.commit()
        return user

    @staticmethod
    def change_role(actor, user, new_role):
        """Change a user's role.

        With single-table inheritance the ``role`` column is the polymorphic
        discriminator: it decides which subclass a row is loaded as. The
        column is updated directly (bypassing the ORM instance) and the old
        instance is expunged so the caller can reload the row as the correct
        subclass (Employee/SecurityAnalyst/Administrator).
        """
        if new_role not in ROLES:
            raise ValueError("Invalid role.")
        if new_role == user.role:
            return False
        db.session.execute(update(User).where(User.id == user.id).values(role=new_role))
        AuditService.log_action(
            actor,
            "role_change",
            f"{actor.full_name} changed the role of {user.email} to {ROLE_LABELS[new_role]}.",
        )
        # Expunge before commit so the caller can still read the id and reload
        # the row as its new subclass without a DetachedInstanceError.
        db.session.expunge(user)
        db.session.commit()
        return True

    @staticmethod
    def set_active(actor, user, active):
        if user.id == actor.id and not active:
            raise ValueError("You cannot deactivate your own account.")
        user.active = bool(active)
        AuditService.log_action(
            actor,
            "user_updated",
            f"{actor.full_name} {'deactivated' if not active else 'activated'} account {user.email}.",
        )
        db.session.commit()

    @staticmethod
    def reset_password(actor, user, new_password):
        errors = UserService.validate_password(new_password)
        if errors:
            raise UserValidationError(errors)
        user.set_password(new_password)
        AuditService.log_action(
            actor,
            "password_reset",
            f"{actor.full_name} reset the password for {user.email}.",
        )
        db.session.commit()

    @staticmethod
    def delete_user(actor, user):
        """Delete an account, keeping the audit trail intact."""
        if user.id == actor.id:
            raise ValueError("You cannot delete your own account.")
        if user.role == "admin" and User.query.filter_by(role="admin").count() <= 1:
            raise ValueError("Cannot delete the last administrator account.")
        if PhishingReport.query.filter_by(reporter_id=user.id).first() is not None:
            raise ValueError("This user has submitted reports - deactivate the account instead.")
        if Investigation.query.filter_by(analyst_id=user.id).first() is not None:
            raise ValueError("This user has investigation records - deactivate the account instead.")

        email = user.email
        # Keep the audit trail readable: null the user reference but keep the name.
        db.session.execute(update(AuditLog).where(AuditLog.user_id == user.id).values(user_id=None))
        db.session.delete(user)
        AuditService.log_action(
            actor,
            "user_deleted",
            f"{actor.full_name} deleted account {email}.",
        )
        db.session.commit()
