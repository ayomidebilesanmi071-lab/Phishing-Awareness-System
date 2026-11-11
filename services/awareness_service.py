"""Awareness article service - admin CRUD with validation and audit."""

from extensions import db
from models.awareness import AwarenessArticle
from models.constants import ARTICLE_CATEGORIES
from services.audit_service import AuditService


class AwarenessValidationError(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("Article validation failed")


class AwarenessService:
    """Business logic for awareness articles (admin-managed content)."""

    @staticmethod
    def validate_article(data):
        errors = {}
        title = (data.get("title") or "").strip()
        category = (data.get("category") or "").strip()
        content = (data.get("content") or "").strip()

        if not title:
            errors["title"] = "Title is required."
        elif len(title) > 200:
            errors["title"] = "Title must be 200 characters or fewer."

        if category not in ARTICLE_CATEGORIES:
            errors["category"] = "Select a valid category."

        if not content:
            errors["content"] = "Article content is required."
        elif len(content) > 100000:
            errors["content"] = "Article is too long (100,000 characters max)."

        if errors:
            raise AwarenessValidationError(errors)
        return {"title": title, "category": category, "content": content}

    @staticmethod
    def create(actor, data):
        cleaned = AwarenessService.validate_article(data)
        article = AwarenessArticle(**cleaned)
        db.session.add(article)
        db.session.flush()
        AuditService.log_action(
            actor,
            "article_created",
            f"{actor.full_name} created awareness article #{article.id} '{article.title}'.",
        )
        db.session.commit()
        return article

    @staticmethod
    def update(actor, article, data):
        cleaned = AwarenessService.validate_article(data)
        article.title = cleaned["title"]
        article.category = cleaned["category"]
        article.content = cleaned["content"]
        AuditService.log_action(
            actor,
            "article_updated",
            f"{actor.full_name} updated awareness article #{article.id} '{article.title}'.",
        )
        db.session.commit()

    @staticmethod
    def delete(actor, article):
        title = article.title
        db.session.delete(article)
        AuditService.log_action(
            actor,
            "article_deleted",
            f"{actor.full_name} deleted awareness article '{title}'.",
        )
        db.session.commit()
