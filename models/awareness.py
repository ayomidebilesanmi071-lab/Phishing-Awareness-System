"""Awareness article model."""

from datetime import datetime

from extensions import db


class AwarenessArticle(db.Model):
    """A cybersecurity awareness article shown in the Awareness Center."""

    __tablename__ = "awareness_articles"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False, default="phishing")
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<AwarenessArticle id={self.id} title={self.title!r}>"
