"""Audit trail service.

Every important security action (report submitted, status changed, user
created, article edited...) is recorded in the ``audit_logs`` table by this
service so the system always has a defensible "who did what, when".
"""

from extensions import db
from models.report import AuditLog


class AuditService:
    """Creates and queries audit log entries."""

    @staticmethod
    def log_action(user, action, description, report=None):
        """Record one audit entry. ``user`` is the acting account."""
        entry = AuditLog(
            user_id=user.id,
            user_name=user.full_name,
            action=action,
            report_id=report.id if report is not None else None,
            description=description,
        )
        db.session.add(entry)
        return entry

    @staticmethod
    def recent(limit=20):
        """Return the most recent audit entries."""
        return (
            AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()
        )
