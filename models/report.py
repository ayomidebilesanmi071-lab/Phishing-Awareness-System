"""Report, status history and audit log models."""

from datetime import datetime

from extensions import db
from models.constants import ATTACK_TYPES, SEVERITIES, STATUSES


class PhishingReport(db.Model):
    """A suspicious message submitted by an employee."""

    __tablename__ = "phishing_reports"

    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    sender_address = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    suspicious_link = db.Column(db.String(1000), nullable=True)
    message_content = db.Column(db.Text, nullable=True)
    date_received = db.Column(db.Date, nullable=True)
    attack_type = db.Column(db.String(40), nullable=False, default="phishing")
    severity = db.Column(db.String(20), nullable=False, default="low")
    status = db.Column(db.String(30), nullable=False, default="pending", index=True)
    comments = db.Column(db.Text, nullable=True)
    attachment_filename = db.Column(db.String(255), nullable=True)
    attachment_original_name = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # --- Relationships ---------------------------------------------------------
    reporter = db.relationship("User", back_populates="reports", foreign_keys=[reporter_id])
    status_history = db.relationship(
        "StatusHistory",
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="StatusHistory.changed_at",
    )
    investigation = db.relationship(
        "Investigation",
        back_populates="report",
        uselist=False,
        cascade="all, delete-orphan",
    )
    audit_entries = db.relationship(
        "AuditLog",
        back_populates="report",
        foreign_keys="AuditLog.report_id",
        cascade="all, delete-orphan",
    )

    # --- Convenience display properties ----------------------------------------
    @property
    def attack_type_label(self):
        return ATTACK_TYPES.get(self.attack_type, self.attack_type.title())

    @property
    def status_label(self):
        return STATUSES.get(self.status, self.status.replace("_", " ").title())

    @property
    def severity_label(self):
        return SEVERITIES.get(self.severity, self.severity.title())

    @property
    def has_attachment(self):
        return bool(self.attachment_filename)

    # --- Behaviour -----------------------------------------------------------------
    def update_status(self, new_status, changed_by):
        """Change the report status and record the transition in history.

        Encapsulation: callers only say *what* changed; this method is the
        single place that guarantees every transition is persisted.
        Returns False when the status did not change (no-op).
        """
        if new_status not in STATUSES:
            raise ValueError(f"Invalid status: {new_status!r}")
        if new_status == self.status:
            return False
        previous = self.status
        self.status = new_status
        db.session.add(
            StatusHistory(
                report_id=self.id,
                previous_status=previous,
                new_status=new_status,
                changed_by=changed_by,
            )
        )
        return True

    def __repr__(self):
        return f"<PhishingReport id={self.id} status={self.status!r} subject={self.subject!r}>"


class StatusHistory(db.Model):
    """One row per status transition of a report (auditable history)."""

    __tablename__ = "status_history"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("phishing_reports.id"), nullable=False, index=True)
    previous_status = db.Column(db.String(30), nullable=False)
    new_status = db.Column(db.String(30), nullable=False)
    changed_by = db.Column(db.String(120), nullable=False)
    changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    report = db.relationship("PhishingReport", back_populates="status_history")

    def __repr__(self):
        return f"<StatusHistory report={self.report_id} {self.previous_status}->{self.new_status}>"


class AuditLog(db.Model):
    """Audit trail of important security actions (who did what, when)."""

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    user_name = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(50), nullable=False, index=True)
    report_id = db.Column(db.Integer, db.ForeignKey("phishing_reports.id"), nullable=True)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    user = db.relationship("User", foreign_keys=[user_id])
    report = db.relationship("PhishingReport", back_populates="audit_entries", foreign_keys=[report_id])

    def __repr__(self):
        return f"<AuditLog id={self.id} action={self.action!r} at={self.created_at}>"
