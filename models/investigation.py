"""Investigation model - analyst workflow for a single report."""

from datetime import datetime

from extensions import db


class Investigation(db.Model):
    """An analyst's investigation of one phishing report.

    There is at most one investigation per report (one-to-one). Findings and
    analyst notes accumulate on the same record, and every analyst action is
    also mirrored in the audit log by the investigation service.
    """

    __tablename__ = "investigations"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("phishing_reports.id"), unique=True, nullable=False, index=True)
    analyst_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    findings = db.Column(db.Text, nullable=True)
    analyst_notes = db.Column(db.Text, nullable=True)
    classification = db.Column(db.String(30), nullable=True)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    investigated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    report = db.relationship("PhishingReport", back_populates="investigation")
    analyst = db.relationship("User", back_populates="investigations", foreign_keys=[analyst_id])

    # --- Behaviour -----------------------------------------------------------
    def add_findings(self, findings):
        """Replace the investigation findings (called when the analyst saves)."""
        self.findings = (findings or "").strip()

    def add_note(self, note, author_name):
        """Append a timestamped note to the investigation log.

        Returns False when the note is empty so callers can skip auditing.
        """
        note = (note or "").strip()
        if not note:
            return False
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        entry = f"[{timestamp}] {author_name}: {note}"
        self.analyst_notes = "\n".join([self.analyst_notes, entry]) if self.analyst_notes else entry
        return True

    def classify(self, classification):
        """Store the investigation outcome classification."""
        self.classification = classification

    def __repr__(self):
        return f"<Investigation id={self.id} report={self.report_id} classification={self.classification!r}>"
