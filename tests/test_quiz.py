"""Quiz tests: grading, storage, feedback and access control."""

from extensions import db as _db
from models.quiz import QuizQuestion, QuizResult
from services.quiz_service import QuizService


def _seed_questions(app, answers):
    with app.app_context():
        ids = []
        for i, correct in enumerate(answers, start=1):
            q = QuizQuestion(
                question=f"Question {i}",
                option_a="Alpha", option_b="Bravo", option_c="Charlie", option_d="Delta",
                correct_answer=correct,
            )
            _db.session.add(q)
            _db.session.flush()
            ids.append(q.id)
        _db.session.commit()
        return ids


def test_quiz_grading_and_feedback(app):
    with app.app_context():
        questions = [
            QuizQuestion(question="q", option_a="a", option_b="b", option_c="c", option_d="d", correct_answer="a"),
            QuizQuestion(question="q", option_a="a", option_b="b", option_c="c", option_d="d", correct_answer="b"),
            QuizQuestion(question="q", option_a="a", option_b="b", option_c="c", option_d="d", correct_answer="c"),
        ]
        for q in questions:
            _db.session.add(q)
        _db.session.commit()

        score, total = QuizService.grade(questions, {questions[0].id: "a", questions[1].id: "a", questions[2].id: "c"})
        assert (score, total) == (2, 3)

        # Feedback thresholds.
        assert QuizService.feedback(95)[0] == "Excellent"
        assert QuizService.feedback(70)[0] == "Good job"
        assert QuizService.feedback(50)[0] == "Fair"
        assert QuizService.feedback(20)[0] == "Needs improvement"


def test_quiz_submission_stores_result(client, create_user, login, app):
    answers = ["a", "b", "c", "d", "a", "b", "c", "d", "a", "b"]
    # Answer 'a' everywhere: exactly the questions whose correct answer is 'a'.
    question_ids = _seed_questions(app, answers)
    user_id = create_user(role="employee", email="quiz@test.local")
    login("quiz@test.local")

    data = {f"question_{qid}": "a" for qid in question_ids}
    response = client.post("/awareness/quiz", data=data, follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        result = QuizResult.query.filter_by(user_id=user_id).first()
        assert result is not None
        assert result.score == 3  # 'a' is correct for 3 of the 10 questions
        assert result.total_questions == 10

    assert b"3 / 10" in response.data
    assert b"30%" in response.data


def test_quiz_requires_authentication(client):
    response = client.get("/awareness/quiz")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_user_cannot_view_others_quiz_results(client, create_user, login, app):
    owner = create_user(role="employee", email="owner@test.local")
    other = create_user(role="employee", email="other@test.local")

    with app.app_context():
        result = QuizResult(user_id=owner, score=9, total_questions=10)
        _db.session.add(result)
        _db.session.commit()
        result_id = result.id

    login("other@test.local")
    response = client.get(f"/awareness/quiz/result/{result_id}")
    assert response.status_code == 302  # redirected away with a flash message


def test_quiz_history_page(client, create_user, login, app):
    user_id = create_user(role="employee", email="history@test.local")
    with app.app_context():
        _db.session.add(QuizResult(user_id=user_id, score=7, total_questions=10))
        _db.session.commit()

    login("history@test.local")
    response = client.get("/awareness/quiz/history")
    assert response.status_code == 200
    assert b"70%" in response.data
