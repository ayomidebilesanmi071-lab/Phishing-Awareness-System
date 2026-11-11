"""Administrator routes - system management.

Only administrators can access these routes; analysts and employees get 403.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

from extensions import db
from models.awareness import AwarenessArticle
from models.constants import ARTICLE_CATEGORIES, ROLE_LABELS, ROLES

ROLE_OPTIONS = [(r, ROLE_LABELS.get(r, r)) for r in ROLES]
from models.quiz import QuizResult
from models.report import PhishingReport
from models.user import User
from routes import role_required
from services.audit_service import AuditService
from services.awareness_service import AwarenessService, AwarenessValidationError
from services.report_service import ReportService
from services.user_service import UserService, UserValidationError

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@role_required("admin")
def dashboard():
    stats = ReportService.stats()
    users_by_role = {role: User.query.filter_by(role=role).count() for role in ROLES}
    articles_count = AwarenessArticle.query.count()
    quizzes_taken = QuizResult.query.count()
    avg = db.session.execute(
        db.select(db.func.avg(QuizResult.score * 100.0 / QuizResult.total_questions))
    ).scalar()
    avg_score = round(avg) if avg is not None else None
    recent_audit = AuditService.recent(15)
    return render_template(
        "admin/dashboard.html",
        stats=stats,
        users_by_role=users_by_role,
        articles_count=articles_count,
        quizzes_taken=quizzes_taken,
        avg_score=avg_score,
        recent_audit=recent_audit,
        active_nav="dashboard",
    )


# ---------------------------------------------------------------------- #
# User management
# ---------------------------------------------------------------------- #
@admin_bp.route("/users")
@role_required("admin")
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=all_users, active_nav="users")


@admin_bp.route("/users/new", methods=["GET", "POST"])
@role_required("admin")
def new_user():
    if request.method == "POST":
        try:
            user = UserService.create_user(
                current_user,
                request.form.get("full_name", ""),
                request.form.get("email", ""),
                request.form.get("password", ""),
                request.form.get("role", ""),
            )
        except UserValidationError as exc:
            return (
                render_template(
                    "admin/user_form.html",
                    form_data=request.form,
                    form_errors=exc.errors,
                    role_options=ROLE_OPTIONS,
                    active_nav="users",
                ),
                400,
            )
        flash(f"Account created for {user.email} ({ROLE_LABELS[user.role]}).", "success")
        return redirect(url_for("admin.users"))

    return render_template(
        "admin/user_form.html",
        form_data={},
        form_errors={},
        role_options=ROLE_OPTIONS,
        active_nav="users",
    )


@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def edit_user(user_id):
    user = db.get_or_404(User, user_id)
    if request.method == "POST":
        try:
            if (request.form.get("role") or "").strip() != user.role:
                UserService.change_role(current_user, user, (request.form.get("role") or "").strip())
                # The discriminator changed, so reload the row as its new class.
                user = db.get_or_404(User, user.id)
            active = request.form.get("active") == "on"
            if active != user.is_active:
                UserService.set_active(current_user, user, active)
            new_password = request.form.get("new_password") or ""
            if new_password:
                UserService.reset_password(current_user, user, new_password)
        except (ValueError, UserValidationError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("admin.edit_user", user_id=user.id))
        flash("User updated.", "success")
        return redirect(url_for("admin.users"))

    reports_count = PhishingReport.query.filter_by(reporter_id=user.id).count()
    return render_template(
        "admin/user_form.html",
        editing=user,
        reports_count=reports_count,
        role_options=ROLE_OPTIONS,
        form_data={},
        form_errors={},
        active_nav="users",
    )


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def delete_user(user_id):
    user = db.get_or_404(User, user_id)
    try:
        UserService.delete_user(current_user, user)
        flash("User account deleted.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.users"))


# ---------------------------------------------------------------------- #
# Awareness article management
# ---------------------------------------------------------------------- #
@admin_bp.route("/articles")
@role_required("admin")
def articles():
    all_articles = AwarenessArticle.query.order_by(AwarenessArticle.created_at.desc()).all()
    return render_template("admin/articles.html", articles=all_articles, active_nav="articles")


@admin_bp.route("/articles/new", methods=["GET", "POST"])
@role_required("admin")
def new_article():
    if request.method == "POST":
        try:
            article = AwarenessService.create(current_user, request.form)
        except AwarenessValidationError as exc:
            return (
                render_template(
                    "admin/article_form.html",
                    form_data=request.form,
                    form_errors=exc.errors,
                    categories=ARTICLE_CATEGORIES,
                    active_nav="articles",
                ),
                400,
            )
        flash(f"Article '{article.title}' published.", "success")
        return redirect(url_for("admin.articles"))

    return render_template(
        "admin/article_form.html",
        form_data={},
        form_errors={},
        categories=ARTICLE_CATEGORIES,
        active_nav="articles",
    )


@admin_bp.route("/articles/<int:article_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def edit_article(article_id):
    article = db.get_or_404(AwarenessArticle, article_id)
    if request.method == "POST":
        try:
            AwarenessService.update(current_user, article, request.form)
        except AwarenessValidationError as exc:
            return (
                render_template(
                    "admin/article_form.html",
                    form_data=request.form,
                    form_errors=exc.errors,
                    categories=ARTICLE_CATEGORIES,
                    editing=article,
                    active_nav="articles",
                ),
                400,
            )
        flash("Article updated.", "success")
        return redirect(url_for("admin.articles"))

    return render_template(
        "admin/article_form.html",
        form_data={"title": article.title, "category": article.category, "content": article.content},
        form_errors={},
        categories=ARTICLE_CATEGORIES,
        editing=article,
        active_nav="articles",
    )


@admin_bp.route("/articles/<int:article_id>/delete", methods=["POST"])
@role_required("admin")
def delete_article(article_id):
    article = db.get_or_404(AwarenessArticle, article_id)
    AwarenessService.delete(current_user, article)
    flash("Article deleted.", "success")
    return redirect(url_for("admin.articles"))
