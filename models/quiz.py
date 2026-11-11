"""Quiz models - questions and per-user results."""

from datetime import datetime

from extensions import db


class QuizQuestion(db.Model):
    """A multiple-choice quiz question (answers stored as a/b/c/d)."""

    __tablename__ = "quiz_questions"

    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(255), nullable=False)
    option_b = db.Column(db.String(255), nullable=False)
    option_c = db.Column(db.String(255), nullable=False)
    option_d = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)  # 'a' | 'b' | 'c' | 'd'

    def is_correct(self, answer):
        """True when the submitted choice matches the correct answer."""
        return (answer or "").strip().lower() == self.correct_answer

    def options(self):
        """Return the four options as (key, text) pairs for templates."""
        return [
            ("a", self.option_a),
            ("b", self.option_b),
            ("c", self.option_c),
            ("d", self.option_d),
        ]

    def __repr__(self):
        return f"<QuizQuestion id={self.id}>"


class QuizResult(db.Model):
    """A user's score for one completed quiz attempt."""

    __tablename__ = "quiz_results"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", back_populates="quiz_results", foreign_keys=[user_id])

    @property
    def percentage(self):
        """Percentage score rounded to the nearest integer."""
        if not self.total_questions:
            return 0
        return round(self.score * 100 / self.total_questions)

    def __repr__(self):
        return f"<QuizResult id={self.id} score={self.score}/{self.total_questions}>"
