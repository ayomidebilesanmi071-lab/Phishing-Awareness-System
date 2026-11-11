"""Security analyst routes - investigation dashboard and workflow.

Admins may also use these routes (they are a superset of analysts) but
employees never can.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

from extensions import db
from models.constants import ATTACK_TYPES, CLASSIFICATIONS, SEVERITIES, STATUSES
from models.report import AuditLog, PhishingReport, StatusHistory
from routes import role_required
from services.audit_service import AuditService
from services.investigation_service import InvestigationService
from services.report_service import ReportService

analyst_bp = Blueprint("analyst", __name__, url_prefix="/analyst")

REPORTS_PER_PAGE = 15
HISTORY_PER_PAGE = 30


def _pct(count, total):
    return round(count * 100 / total) if total else 0


@analyst_bp.route("/")
@role_required("analyst", "admin")
def dashboard():
    stats = ReportService.stats()
    status_chart = [
        {"key": key, "label": label, "count": stats["status_counts"][key],
         "pct": _pct(stats["status_counts"][key], stats["total"])}
        for key, label in STATUSES.items()
    ]
    attack_chart = [
        {"key": key, "label": label, "count": stats["attack_counts"][key],
         "pct": _pct(stats["attack_counts"][key], stats["total"])}
        for key, label in ATTACK_TYPES.items()
    ]
    severity_chart = [
        {"key": key, "label": label, "count": stats["severity_counts"][key],
         "pct": _pct(stats["severity_counts"][key], stats["total"])}
        for key, label in SEVERITIES.items()
    ]
    return render_template(
        "analyst/dashboard.html",
        stats=stats,
        status_chart=status_chart,
        attack_chart=attack_chart,
        severity_chart=severity_chart,
        active_nav="dashboard",
    )


@analyst_bp.route("/reports")
@role_required("analyst", "admin")
def reports():
    filters = {
        "q": (request.args.get("q") or "").strip(),
        "status": (request.args.get("status") or "").strip(),
        "severity": (request.args.get("severity") or "").strip(),
        "attack_type": (request.args.get("attack_type") or "").strip(),
        "date_from": (request.args.get("date_from") or "").strip(),
        "date_to": (request.args.get("date_to") or "").strip(),
    }
    query = ReportService.query_reports(
        search=filters["q"],
        status=filters["status"],
        severity=filters["severity"],
        attack_type=filters["attack_type"],
        date_from=filters["date_from"],
        date_to=filters["date_to"],
    )
    pagination = db.paginate(
        query,
        page=request.args.get("page", 1, type=int),
        per_page=REPORTS_PER_PAGE,
        error_out=False,
    )
    return render_template(
        "analyst/reports.html",
        pagination=pagination,
        filters=filters,
        active_nav="reports",
    )


@analyst_bp.route("/reports/<int:report_id>")
@role_required("analyst", "admin")
def report_detail(report_id):
    report = db.get_or_404(PhishingReport, report_id)
    audit_entries = (
        AuditLog.query.filter_by(report_id=report.id)
        .order_by(AuditLog.created_at.desc())
        .all()
    )
    return render_template(
        "analyst/report_detail.html",
        report=report,
        audit_entries=audit_entries,
        active_nav="reports",
    )


# ---------------------------------------------------------------------- #
# Investigation workflow actions (all POST, all CSRF-protected)
# ---------------------------------------------------------------------- #
@analyst_bp.route("/reports/<int:report_id>/investigate", methods=["POST"])
@role_required("analyst", "admin")
def start_investigation(report_id):
    report = db.get_or_404(PhishingReport, report_id)
    _investigation, created = InvestigationService.start(report, current_user)
    if created:
        flash(f"Investigation started on report #{report.id}.", "success")
    else:
        flash(f"An investigation already exists for report #{report.id}.", "info")
    return redirect(url_for("analyst.report_detail", report_id=report.id))


@analyst_bp.route("/reports/<int:report_id>/findings", methods=["POST"])
@role_required("analyst", "admin")
def add_findings(report_id):
    report = db.get_or_404(PhishingReport, report_id)
    findings = (request.form.get("findings") or "").strip()
    if not findings:
        flash("Findings cannot be empty.", "error")
    else:
        InvestigationService.add_findings(report, current_user, findings)
        flash("Findings saved.", "success")
    return redirect(url_for("analyst.report_detail", report_id=report.id))


@analyst_bp.route("/reports/<int:report_id>/notes", methods=["POST"])
@role_required("analyst", "admin")
def add_note(report_id):
    report = db.get_or_404(PhishingReport, report_id)
    note = (request.form.get("note") or "").strip()
    if not note:
        flash("Note cannot be empty.", "error")
    else:
        InvestigationService.add_note(report, current_user, note)
        flash("Note added.", "success")
    return redirect(url_for("analyst.report_detail", report_id=report.id))


@analyst_bp.route("/reports/<int:report_id>/severity", methods=["POST"])
@role_required("analyst", "admin")
def change_severity(report_id):
    report = db.get_or_404(PhishingReport, report_id)
    severity = (request.form.get("severity") or "").strip()
    try:
        InvestigationService.set_severity(report, current_user, severity)
        flash(f"Severity updated to {SEVERITIES[severity]}.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("analyst.report_detail", report_id=report.id))


@analyst_bp.route("/reports/<int:report_id>/classification", methods=["POST"])
@role_required("analyst", "admin")
def set_classification(report_id):
    report = db.get_or_404(PhishingReport, report_id)
    classification = (request.form.get("classification") or "").strip()
    try:
        InvestigationService.set_classification(report, current_user, classification)
        flash(f"Report #{report.id} classified as {CLASSIFICATIONS[classification]}.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("analyst.report_detail", report_id=report.id))


@analyst_bp.route("/reports/<int:report_id>/status", methods=["POST"])
@role_required("analyst", "admin")
def change_status(report_id):
    report = db.get_or_404(PhishingReport, report_id)
    new_status = (request.form.get("status") or "").strip()
    try:
        InvestigationService.set_status(report, current_user, new_status)
        flash(f"Status changed to {STATUSES[new_status]}.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("analyst.report_detail", report_id=report.id))


@analyst_bp.route("/reports/<int:report_id>/close", methods=["POST"])
@role_required("analyst", "admin")
def close_report(report_id):
    report = db.get_or_404(PhishingReport, report_id)
    note = (request.form.get("closing_note") or "").strip()
    InvestigationService.close(report, current_user, note)
    flash(f"Report #{report.id} closed.", "success")
    return redirect(url_for("analyst.report_detail", report_id=report.id))


# ---------------------------------------------------------------------- #
# Incident history
# ---------------------------------------------------------------------- #
@analyst_bp.route("/history")
@role_required("analyst", "admin")
def history():
    query = StatusHistory.query.order_by(StatusHistory.changed_at.desc())
    pagination = db.paginate(
        query,
        page=request.args.get("page", 1, type=int),
        per_page=HISTORY_PER_PAGE,
        error_out=False,
    )
    recent_audit = AuditService.recent(12)
    return render_template(
        "analyst/history.html",
        pagination=pagination,
        recent_audit=recent_audit,
        active_nav="history",
    )
