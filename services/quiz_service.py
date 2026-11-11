"""Quiz service - grading and feedback."""

from extensions import db
from models.quiz import QuizQuestion, QuizResult


class QuizService:
    """Grades quiz attempts, stores results and provides feedback."""

    @staticmethod
    def get_questions():
        return QuizQuestion.query.order_by(QuizQuestion.id).all()

    @staticmethod
    def grade(questions, answers):
        """Grade a dict of {question_id: choice} against the questions.

        Returns (score, total_questions). Unanswered questions simply do
        not count towards the score.
        """
        score = sum(1 for q in questions if q.is_correct(answers.get(q.id)))
        return score, len(questions)

    @staticmethod
    def save_result(user, score, total):
        """Persist a quiz attempt for the user."""
        result = QuizResult(user_id=user.id, score=score, total_questions=total)
        db.session.add(result)
        db.session.commit()
        return result

    @staticmethod
    def feedback(percentage):
        """Return (title, message) guidance based on the percentage score."""
        if percentage >= 90:
            return ("Excellent", "Outstanding! You have a strong grasp of phishing risks. "
                    "Keep it up and help your colleagues stay alert.")
        if percentage >= 70:
            return ("Good job", "You know the basics well. Review the awareness articles "
                    "to polish a few details, then try again.")
        if percentage >= 50:
            return ("Fair", "You are on the right track, but there is room for improvement. "
                    "Revisit the awareness articles and retake the quiz.")
        return ("Needs improvement",
                "Please review the awareness materials carefully, then retake the quiz. "
                "Awareness is your best defense against social engineering.")
