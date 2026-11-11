"""User models.

PARS uses **single-table inheritance** to model roles with real OOP:

* ``User`` - the abstract-ish base class holding authentication data and the
  ``role`` discriminator column (polymorphic_on).
* ``Employee`` - can submit phishing reports and take quizzes.
* ``SecurityAnalyst`` - can investigate reports.
* ``Administrator`` - can manage users and awareness content.

Every row lives in one ``users`` table; SQLAlchemy loads each row as the
correct subclass based on the ``role`` value, so ``db.session.get(User, id)``
returns an ``Employee``, ``SecurityAnalyst`` or ``Administrator`` instance
automatically. No user logic is duplicated between the three roles.
"""

from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from models.constants import ROLE_LABELS
from models.investigation import Investigation
from models.report import PhishingReport

# Maps a role name to the polymorphic subclass that implements it.
ROLE_CLASSES = {}


class User(UserMixin, db.Model):
    """Base class for every account in the system."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)          # polymorphic discriminator
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __mapper_args__ = {"polymorphic_on": role, "polymorphic_identity": "user"}

    # --- Relationships (usable by every role) ------------------------------
    reports = db.relationship(
        "PhishingReport",
        back_populates="reporter",
        foreign_keys="PhishingReport.reporter_id",
        lazy="dynamic",
    )
    investigations = db.relationship(
        "Investigation",
        back_populates="analyst",
        foreign_keys="Investigation.analyst_id",
        lazy="dynamic",
    )
    quiz_results = db.relationship(
        "QuizResult",
        back_populates="user",
        foreign_keys="QuizResult.user_id",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # --- Encapsulation: password handling -----------------------------------
    def set_password(self, raw_password):
        """Hash and store a password. Plain text is never kept."""
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        """Verify a plain-text password against the stored hash."""
        return check_password_hash(self.password_hash, raw_password)

    # --- Flask-Login support --------------------------------------------------
    @property
    def is_active(self):
        """Deactivated accounts cannot log in or use the system."""
        return self.active

    # --- Role helpers ----------------------------------------------------------
    @property
    def role_label(self):
        return ROLE_LABELS.get(self.role, self.role.title())

    def has_role(self, *roles):
        """True when the user holds one of the given roles."""
        return self.role in roles

    def __repr__(self):
        return f"<{self.__class__.__name__} id={self.id} email={self.email!r}>"


class Employee(User):
    """An employee who reports suspicious messages and learns via quizzes."""

    __mapper_args__ = {"polymorphic_identity": "employee"}

    def submit_report(self, **fields):
        """Create a PhishingReport owned by this employee.

        Encapsulates report construction so callers never build a report
        without a reporter. Persistence/audit is handled by ReportService.
        """
        report = PhishingReport(reporter_id=self.id, **fields)
        db.session.add(report)
        return report


class SecurityAnalyst(User):
    """A security analyst who investigates reported incidents."""

    __mapper_args__ = {"polymorphic_identity": "analyst"}

    def start_investigation(self, report):
        """Open an investigation for a report and move it to Under Investigation."""
        investigation = Investigation(report_id=report.id, analyst_id=self.id)
        db.session.add(investigation)
        report.update_status("under_investigation", self.full_name)
        return investigation


class Administrator(User):
    """An administrator who manages users, analysts and awareness content."""

    __mapper_args__ = {"polymorphic_identity": "admin"}

    def create_user(self, full_name, email, password, role):
        """Create an account of the requested role (simple factory method).

        Returns the correct subclass instance (Employee, SecurityAnalyst or
        Administrator) so caller code stays role-agnostic.
        """
        user_class = ROLE_CLASSES.get(role)
        if user_class is None:
            raise ValueError(f"Unknown role: {role!r}")
        user = user_class(full_name=full_name, email=email)
        user.set_password(password)
        db.session.add(user)
        return user


# Register subclasses after they are defined (avoids forward references).
ROLE_CLASSES.update(
    employee=Employee,
    analyst=SecurityAnalyst,
    admin=Administrator,
)
