"""Report service - validation, submission, searching, filtering, stats.

All submitted data is validated server-side before it touches the database.
Links are never fetched or executed: they are stored as plain, escaped text.
"""

import re
from datetime import date, datetime
from urllib.parse import urlparse

from extensions import db
from models.constants import ATTACK_TYPES, SEVERITIES, STATUSES
from models.report import PhishingReport
from services.attachment_service import AttachmentError, AttachmentService
from services.audit_service import AuditService

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ReportValidationError(ValueError):
    """Raised when report data fails validation.

    Carries ``errors`` - a dict mapping field names to human-readable
    messages that the templates render next to the offending inputs.
    """

    def __init__(self, errors):
        self.errors = errors
        super().__init__("Report validation failed")


class ReportService:
    """Business logic for phishing reports."""

    MAX_SENDER_LENGTH = 255
    MAX_SUBJECT_LENGTH = 255
    MAX_LINK_LENGTH = 1000
    MAX_CONTENT_LENGTH = 50000
    MAX_COMMENTS_LENGTH = 5000

    # ------------------------------------------------------------------ #
    # Submission
    # ------------------------------------------------------------------ #
    @staticmethod
    def validate_submission(data):
        """Validate a report submission and return cleaned values.

        Raises ReportValidationError with per-field messages on failure.
        """
        errors = {}

        sender = (data.get("sender_address") or "").strip()
        subject = (data.get("subject") or "").strip()
        link = (data.get("suspicious_link") or "").strip()
        content = (data.get("message_content") or "").strip()
        attack_type = (data.get("attack_type") or "").strip().lower()
        date_received = (data.get("date_received") or "").strip()
        comments = (data.get("comments") or "").strip()

        # Sender address
        if not sender:
            errors["sender_address"] = "Sender address is required."
        elif len(sender) > ReportService.MAX_SENDER_LENGTH:
            errors["sender_address"] = "Sender address is too long."
        elif not EMAIL_RE.fullmatch(sender):
            errors["sender_address"] = "Enter a valid sender email address."

        # Subject
        if not subject:
            errors["subject"] = "Subject is required."
        elif len(subject) > ReportService.MAX_SUBJECT_LENGTH:
            errors["subject"] = "Subject is too long (255 characters max)."

        # Suspicious link - validated but NEVER opened, fetched or executed.
        if link:
            if len(link) > ReportService.MAX_LINK_LENGTH:
                errors["suspicious_link"] = "The link is too long."
            else:
                # Detect an explicit scheme (e.g. javascript:...) so that
                # schemes other than http/https are rejected even when the
                # link was submitted without "://".
                if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", link):
                    parsed = urlparse(link)
                else:
                    parsed = urlparse("http://" + link)
                if parsed.scheme not in ("http", "https") or not parsed.netloc:
                    errors["suspicious_link"] = (
                        "Enter a valid http(s) URL. The link is stored as text "
                        "and never opened automatically."
                    )

        # Message content
        if not content:
            errors["message_content"] = "Please describe or paste the message content."
        elif len(content) > ReportService.MAX_CONTENT_LENGTH:
            errors["message_content"] = "Message content is too long."

        # Attack type
        if attack_type not in ATTACK_TYPES:
            errors["attack_type"] = "Select a valid attack type."

        # Date received
        parsed_date = None
        if date_received:
            try:
                parsed_date = datetime.strptime(date_received, "%Y-%m-%d").date()
                if parsed_date > date.today():
                    errors["date_received"] = "Date cannot be in the future."
            except ValueError:
                errors["date_received"] = "Enter a valid date (YYYY-MM-DD)."
        else:
            parsed_date = date.today()

        # Comments
        if len(comments) > ReportService.MAX_COMMENTS_LENGTH:
            errors["comments"] = "Comments are too long."

        if errors:
            raise ReportValidationError(errors)

        return {
            "sender_address": sender,
            "subject": subject,
            "suspicious_link": link or None,
            "message_content": content,
            "attack_type": attack_type,
            "date_received": parsed_date,
            "comments": comments or None,
        }

    @staticmethod
    def submit(reporter, form_data, attachment_file=None):
        """Validate and persist a new report submitted by an employee.

        Returns the created PhishingReport (with its id available after
        the commit). Raises ReportValidationError on bad input.
        """
        cleaned = ReportService.validate_submission(form_data)

        stored_name = original_name = None
        try:
            stored_name, original_name = AttachmentService.save(attachment_file)
        except AttachmentError as exc:
            raise ReportValidationError({"attachment": str(exc)})

        report = reporter.submit_report(
            sender_address=cleaned["sender_address"],
            subject=cleaned["subject"],
            suspicious_link=cleaned["suspicious_link"],
            message_content=cleaned["message_content"],
            attack_type=cleaned["attack_type"],
            date_received=cleaned["date_received"],
            comments=cleaned["comments"],
            attachment_filename=stored_name,
            attachment_original_name=original_name,
        )
        db.session.flush()
        AuditService.log_action(
            reporter,
            "report_submitted",
            f"{reporter.full_name} submitted report #{report.id} "
            f"({report.attack_type_label}).",
            report,
        )
        db.session.commit()
        return report

    # ------------------------------------------------------------------ #
    # Querying / search / filter
    # ------------------------------------------------------------------ #
    @staticmethod
    def query_reports(search=None, status=None, severity=None, attack_type=None,
                      date_from=None, date_to=None):
        """Return a query object filtered by the analyst's criteria."""
        query = PhishingReport.query

        # Free-text search: sender, subject, attack type, or report ID.
        search = (search or "").strip()
        if search:
            like = f"%{search}%"
            conditions = [
                PhishingReport.sender_address.ilike(like),
                PhishingReport.subject.ilike(like),
                PhishingReport.attack_type.ilike(like),
            ]
            if search.isdigit():
                conditions.append(PhishingReport.id == int(search))
            query = query.filter(db.or_(*conditions))

        if status in STATUSES:
            query = query.filter(PhishingReport.status == status)
        if severity in SEVERITIES:
            query = query.filter(PhishingReport.severity == severity)
        if attack_type in ATTACK_TYPES:
            query = query.filter(PhishingReport.attack_type == attack_type)

        if date_from:
            try:
                day = datetime.strptime(date_from, "%Y-%m-%d").date()
                query = query.filter(PhishingReport.created_at >= datetime.combine(day, datetime.min.time()))
            except ValueError:
                pass
        if date_to:
            try:
                day = datetime.strptime(date_to, "%Y-%m-%d").date()
                query = query.filter(PhishingReport.created_at <= datetime.combine(day, datetime.max.time()))
            except ValueError:
                pass

        return query.order_by(PhishingReport.created_at.desc())

    @staticmethod
    def status_counts():
        return {s: PhishingReport.query.filter_by(status=s).count() for s in STATUSES}

    @staticmethod
    def severity_counts():
        return {s: PhishingReport.query.filter_by(severity=s).count() for s in SEVERITIES}

    @staticmethod
    def attack_type_counts():
        return {t: PhishingReport.query.filter_by(attack_type=t).count() for t in ATTACK_TYPES}

    @staticmethod
    def total():
        return PhishingReport.query.count()

    @staticmethod
    def recent(limit=8):
        return (
            PhishingReport.query.order_by(PhishingReport.created_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def stats():
        """Aggregated statistics used by the analyst/admin dashboards."""
        status_counts = ReportService.status_counts()
        severity_counts = ReportService.severity_counts()
        return {
            "total": ReportService.total(),
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "attack_counts": ReportService.attack_type_counts(),
            "high_severity": severity_counts["high"] + severity_counts["critical"],
            "recent": ReportService.recent(8),
        }
