"""Employee routes - reporting and personal dashboard."""

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   send_file, url_for)
from flask_login import current_user

from extensions import db
from models.constants import ATTACK_TYPES
from models.report import PhishingReport
from routes import role_required
from services.attachment_service import AttachmentService
from services.report_service import ReportService, ReportValidationError

employee_bp = Blueprint("employee", __name__, url_prefix="/employee")


@employee_bp.route("/")
@role_required("employee")
def dashboard():
    reports = current_user.reports
    total = reports.count()
    pending = reports.filter_by(status="pending").count()
    confirmed = reports.filter_by(status="confirmed_phishing").count()
    under_investigation = reports.filter_by(status="under_investigation").count()
    recent = reports.order_by(PhishingReport.created_at.desc()).limit(5).all()
    return render_template(
        "employee/dashboard.html",
        total=total,
        pending=pending,
        confirmed=confirmed,
        under_investigation=under_investigation,
        recent=recent,
        active_nav="dashboard",
    )


@employee_bp.route("/report/new", methods=["GET", "POST"])
@role_required("employee")
def submit_report():
    if request.method == "POST":
        try:
            report = ReportService.submit(current_user, request.form,
                                          request.files.get("attachment"))
        except ReportValidationError as exc:
            return (
                render_template(
                    "employee/submit_report.html",
                    form_data=request.form,
                    form_errors=exc.errors,
                    attack_types=ATTACK_TYPES,
                    active_nav="report",
                ),
                400,
            )
        flash(f"Report #{report.id} submitted. The security team has been notified.", "success")
        return redirect(url_for("employee.report_detail", report_id=report.id))

    return render_template(
        "employee/submit_report.html",
        form_data={},
        form_errors={},
        attack_types=ATTACK_TYPES,
        active_nav="report",
    )


@employee_bp.route("/reports")
@role_required("employee")
def my_reports():
    status = (request.args.get("status") or "").strip()
    query = current_user.reports
    if status:
        query = query.filter_by(status=status)
    pagination = db.paginate(
        query.order_by(PhishingReport.created_at.desc()),
        page=request.args.get("page", 1, type=int),
        per_page=10,
        error_out=False,
    )
    return render_template(
        "employee/my_reports.html",
        pagination=pagination,
        status=status,
        active_nav="reports",
    )


@employee_bp.route("/reports/<int:report_id>")
@role_required("employee")
def report_detail(report_id):
    # Employees may only ever see their own reports (404 otherwise).
    report = db.first_or_404(
        db.select(PhishingReport).where(
            PhishingReport.id == report_id,
            PhishingReport.reporter_id == current_user.id,
        )
    )
    return render_template(
        "employee/report_detail.html",
        report=report,
        active_nav="reports",
    )


@employee_bp.route("/reports/<int:report_id>/attachment")
@role_required("employee", "analyst", "admin")
def attachment(report_id):
    """Download the evidence attachment (as an attachment, never rendered)."""
    report = db.get_or_404(PhishingReport, report_id)
    if current_user.role == "employee" and report.reporter_id != current_user.id:
        abort(404)
    if not report.attachment_filename:
        abort(404)
    try:
        path = AttachmentService.resolve_path(report.attachment_filename)
    except FileNotFoundError:
        abort(404)
    return send_file(
        path,
        as_attachment=True,
        download_name=report.attachment_original_name or "attachment",
    )
