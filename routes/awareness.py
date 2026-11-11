"""Awareness Center routes - articles and the phishing awareness quiz."""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models.awareness import AwarenessArticle
from models.constants import ARTICLE_CATEGORIES
from models.quiz import QuizResult
from services.quiz_service import QuizService

awareness_bp = Blueprint("awareness", __name__, url_prefix="/awareness")


@awareness_bp.route("/")
@login_required
def articles():
    category = (request.args.get("category") or "").strip()
    query = AwarenessArticle.query
    if category in ARTICLE_CATEGORIES:
        query = query.filter_by(category=category)
    all_articles = query.order_by(AwarenessArticle.created_at.desc()).all()
    return render_template(
        "awareness/articles.html",
        articles=all_articles,
        category=category,
        categories=ARTICLE_CATEGORIES,
        active_nav="awareness",
    )


@awareness_bp.route("/article/<int:article_id>")
@login_required
def article_detail(article_id):
    article = db.get_or_404(AwarenessArticle, article_id)
    return render_template(
        "awareness/article_detail.html",
        article=article,
        active_nav="awareness",
    )


@awareness_bp.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz():
    questions = QuizService.get_questions()
    if not questions:
        flash("No quiz questions are available yet. Check back soon.", "warning")
        return redirect(url_for("awareness.articles"))

    if request.method == "POST":
        answers = {}
        for question in questions:
            value = request.form.get(f"question_{question.id}", "")
            if value in ("a", "b", "c", "d"):
                answers[question.id] = value
        score, total = QuizService.grade(questions, answers)
        result = QuizService.save_result(current_user, score, total)
        return redirect(url_for("awareness.quiz_result", result_id=result.id))

    return render_template("awareness/quiz.html", questions=questions, active_nav="quiz")


@awareness_bp.route("/quiz/result/<int:result_id>")
@login_required
def quiz_result(result_id):
    result = db.get_or_404(QuizResult, result_id)
    if result.user_id != current_user.id:
        flash("You can only view your own quiz results.", "error")
        return redirect(url_for("awareness.quiz"))
    percentage = result.percentage
    feedback_title, feedback_text = QuizService.feedback(percentage)
    return render_template(
        "awareness/quiz_result.html",
        result=result,
        percentage=percentage,
        feedback_title=feedback_title,
        feedback_text=feedback_text,
        active_nav="quiz",
    )


@awareness_bp.route("/quiz/history")
@login_required
def quiz_history():
    results = (
        QuizResult.query.filter_by(user_id=current_user.id)
        .order_by(QuizResult.completed_at.desc())
        .all()
    )
    return render_template(
        "awareness/quiz_history.html",
        results=results,
        active_nav="quiz",
    )
