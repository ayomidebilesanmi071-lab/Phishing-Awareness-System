"""Model registry.

Importing this package registers every model with SQLAlchemy so that
``db.create_all()`` creates all tables and relationship strings resolve.
"""

from models.user import Administrator, Employee, SecurityAnalyst, User
from models.report import AuditLog, PhishingReport, StatusHistory
from models.investigation import Investigation
from models.awareness import AwarenessArticle
from models.quiz import QuizQuestion, QuizResult

__all__ = [
    "User",
    "Employee",
    "SecurityAnalyst",
    "Administrator",
    "PhishingReport",
    "StatusHistory",
    "AuditLog",
    "Investigation",
    "AwarenessArticle",
    "QuizQuestion",
    "QuizResult",
]
