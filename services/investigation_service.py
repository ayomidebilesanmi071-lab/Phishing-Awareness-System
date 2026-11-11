"""Investigation service - the analyst workflow.

Coordinates: starting an investigation, adding findings/notes, changing
severity, classifying, changing status and closing a report. Every important
transition is recorded in the status history and the audit log.
"""

from extensions import db
from models.constants import CLASSIFICATIONS, SEVERITIES, STATUSES
from models.investigation import Investigation
from models.user import SecurityAnalyst
from services.audit_service import AuditService


class InvestigationService:
    """Business logic for investigating phishing reports."""

    @staticmethod
    def start(report, actor):
        """Open an investigation and move the report to Under Investigation.

        Returns (investigation, created). When a SecurityAnalyst starts the
        investigation the polymorphic ``start_investigation`` method is used;
        other actors (e.g. an administrator filling in) fall back to direct
        creation.
        """
        if report.investigation is not None:
            return report.investigation, False

        if isinstance(actor, SecurityAnalyst):
            investigation = actor.start_investigation(report)
        else:
            investigation = Investigation(report_id=report.id, analyst_id=actor.id)
            db.session.add(investigation)
            report.update_status("under_investigation", actor.full_name)

        db.session.flush()
        AuditService.log_action(
            actor,
            "investigation_started",
            f"{actor.full_name} started an investigation on report #{report.id}.",
            report,
        )
        db.session.commit()
        return investigation, True

    @staticmethod
    def add_findings(report, actor, findings):
        """Save (replace) the analyst's investigation findings."""
        investigation = InvestigationService._ensure(report, actor)
        investigation.add_findings(findings)
        AuditService.log_action(
            actor,
            "findings_added",
            f"{actor.full_name} added findings to the investigation for report #{report.id}.",
            report,
        )
        db.session.commit()

    @staticmethod
    def add_note(report, actor, note):
        """Append a timestamped note to the investigation log."""
        investigation = InvestigationService._ensure(report, actor)
        if investigation.add_note(note, actor.full_name):
            AuditService.log_action(
                actor,
                "note_added",
                f"{actor.full_name} added an investigation note to report #{report.id}.",
                report,
            )
            db.session.commit()

    @staticmethod
    def set_severity(report, actor, severity):
        """Change the severity of a report (Low/Medium/High/Critical)."""
        if severity not in SEVERITIES:
            raise ValueError("Invalid severity level.")
        if severity == report.severity:
            return
        report.severity = severity
        AuditService.log_action(
            actor,
            "severity_change",
            f"{actor.full_name} set severity of report #{report.id} to {SEVERITIES[severity]}.",
            report,
        )
        db.session.commit()

    @staticmethod
    def set_classification(report, actor, classification):
        """Classify the outcome of the investigation."""
        if classification not in CLASSIFICATIONS:
            raise ValueError("Invalid classification.")
        investigation = InvestigationService._ensure(report, actor)
        investigation.classify(classification)
        AuditService.log_action(
            actor,
            "classification",
            f"{actor.full_name} classified report #{report.id} as {CLASSIFICATIONS[classification]}.",
            report,
        )
        db.session.commit()

    @staticmethod
    def set_status(report, actor, new_status):
        """Change the report status (records StatusHistory + audit log).

        Moving a report to Under Investigation also opens an investigation
        record if none exists yet.
        """
        if new_status not in STATUSES:
            raise ValueError("Invalid status.")
        if new_status == report.status:
            return

        previous = report.status
        report.update_status(new_status, actor.full_name)

        if new_status == "under_investigation" and report.investigation is None:
            db.session.add(Investigation(report_id=report.id, analyst_id=actor.id))

        AuditService.log_action(
            actor,
            "status_change",
            f"{actor.full_name} changed report #{report.id} from "
            f"{STATUSES[previous]} to {STATUSES[new_status]}.",
            report,
        )
        db.session.commit()

    @staticmethod
    def close(report, actor, note=None):
        """Close the incident, optionally with a closing note."""
        investigation = report.investigation
        if note and note.strip():
            if investigation is None:
                investigation = InvestigationService._ensure(report, actor)
            investigation.add_note(note, actor.full_name)
        report.update_status("closed", actor.full_name)
        AuditService.log_action(
            actor,
            "report_closed",
            f"{actor.full_name} closed report #{report.id}.",
            report,
        )
        db.session.commit()

    # ------------------------------------------------------------------ #
    @staticmethod
    def _ensure(report, actor):
        """Return the report's investigation, creating it if needed."""
        if report.investigation is not None:
            return report.investigation
        investigation = Investigation(report_id=report.id, analyst_id=actor.id)
        db.session.add(investigation)
        report.update_status("under_investigation", actor.full_name)
        db.session.flush()
        return investigation
