"""Model and OOP tests: inheritance, relationships, behaviour."""

from datetime import date

from extensions import db as _db
from models.investigation import Investigation
from models.quiz import QuizQuestion, QuizResult
from models.report import AuditLog, PhishingReport, StatusHistory
from models.user import Administrator, Employee, SecurityAnalyst, User


def test_single_table_inheritance_roles(app, create_user, get_user):
    employee_id = create_user(role="employee", email="e@test.local")
    analyst_id = create_user(role="analyst", email="a@test.local")
    admin_id = create_user(role="admin", email="ad@test.local")

    with app.app_context():
        employee = _db.session.get(User, employee_id)
        analyst = _db.session.get(User, analyst_id)
        admin = _db.session.get(User, admin_id)

        # SQLAlchemy loads each row as the correct subclass.
        assert isinstance(employee, Employee)
        assert isinstance(analyst, SecurityAnalyst)
        assert isinstance(admin, Administrator)

        # Discriminator column matches the role.
        assert employee.role == "employee"
        assert analyst.role == "analyst"
        assert admin.role == "admin"

        # Role helper.
        assert employee.has_role("employee")
        assert not employee.has_role("admin")
        assert analyst.has_role("analyst")
        assert admin.has_role("admin", "analyst")

        # Role labels.
        assert analyst.role_label == "Security Analyst"
        assert admin.role_label == "Administrator"


def test_password_hashing_roundtrip(app):
    with app.app_context():
        user = Employee(full_name="Test", email="hash@test.local")
        user.set_password("SuperSecret123")
        _db.session.add(user)
        _db.session.commit()
        stored = user.password_hash
        assert stored != "SuperSecret123"
        assert user.check_password("SuperSecret123")
        assert not user.check_password("SuperSecret1234")
        # Hashes differ across users with the same password (salting).
        other = Employee(full_name="Other", email="other@test.local")
        other.set_password("SuperSecret123")
        assert other.password_hash != stored


def test_administrator_create_user_factory(app):
    with app.app_context():
        admin = Administrator(full_name="Boss", email="boss@test.local")
        admin.set_password("Password123")
        _db.session.add(admin)
        _db.session.commit()

        employee = admin.create_user("New Person", "new@test.local", "Password123", "employee")
        analyst = admin.create_user("Sec Person", "sec@test.local", "Password123", "analyst")
        _db.session.commit()

        assert isinstance(employee, Employee)
        assert isinstance(analyst, SecurityAnalyst)
        assert employee.role == "employee"
        assert analyst.role == "analyst"


def test_report_reporter_relationship(app, create_user):
    employee_id = create_user(role="employee", email="erin@test.local")
    with app.app_context():
        employee = _db.session.get(User, employee_id)
        report = PhishingReport(
            reporter_id=employee.id,
            sender_address="a@evil.example",
            subject="Test",
            message_content="Body",
            attack_type="phishing",
            status="pending",
            date_received=date(2025, 1, 1),
        )
        _db.session.add(report)
        _db.session.commit()

        # Bidirectional relationship works from both sides.
        assert report.reporter is employee
        assert employee.reports.count() == 1
        assert employee.reports.first().id == report.id


def test_employee_submit_report_method(app, get_user):
    with app.app_context():
        employee = Employee(full_name="Erin", email="erin2@test.local")
        employee.set_password("Password123")
        _db.session.add(employee)
        _db.session.commit()

        report = employee.submit_report(
            sender_address="a@evil.example",
            subject="Hello",
            suspicious_link=None,
            message_content="Content",
            attack_type="phishing",
            date_received=date(2025, 1, 1),
            comments=None,
            attachment_filename=None,
            attachment_original_name=None,
        )
        _db.session.commit()
        assert report.reporter_id == employee.id
        assert report.status == "pending"


def test_update_status_records_history(app, create_user):
    employee_id = create_user(role="employee", email="erin@test.local")
    analyst_id = create_user(role="analyst", email="sam@test.local")
    with app.app_context():
        employee = _db.session.get(User, employee_id)
        analyst = _db.session.get(User, analyst_id)
        report = PhishingReport(
            reporter_id=employee.id,
            sender_address="a@evil.example",
            subject="Test",
            message_content="Body",
            attack_type="phishing",
            status="pending",
        )
        _db.session.add(report)
        _db.session.commit()

        assert report.update_status("under_investigation", analyst.full_name) is True
        _db.session.commit()
        assert report.status == "under_investigation"
        history = StatusHistory.query.filter_by(report_id=report.id).all()
        assert len(history) == 1
        assert history[0].previous_status == "pending"
        assert history[0].new_status == "under_investigation"
        assert history[0].changed_by == analyst.full_name

        # No-op transitions are ignored.
        assert report.update_status("under_investigation", analyst.full_name) is False

        # Invalid statuses raise.
        try:
            report.update_status("not-a-status", analyst.full_name)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_investigation_relationships(app, create_user):
    employee_id = create_user(role="employee", email="erin@test.local")
    analyst_id = create_user(role="analyst", email="sam@test.local")
    with app.app_context():
        employee = _db.session.get(User, employee_id)
        analyst = _db.session.get(User, analyst_id)
        report = PhishingReport(
            reporter_id=employee.id, sender_address="a@evil.example",
            subject="S", message_content="B", attack_type="phishing", status="pending",
        )
        _db.session.add(report)
        _db.session.commit()

        investigation = Investigation(report_id=report.id, analyst_id=analyst.id)
        _db.session.add(investigation)
        _db.session.commit()

        assert report.investigation is investigation
        assert investigation.report is report
        assert investigation.analyst is analyst
        assert analyst.investigations.count() == 1

        # Notes are appended with timestamps and author names.
        investigation.add_note("First note", analyst.full_name)
        investigation.add_note("Second note", analyst.full_name)
        assert "First note" in investigation.analyst_notes
        assert "Second note" in investigation.analyst_notes
        assert investigation.add_note("   ", analyst.full_name) is False


def test_audit_log_relationship(app, create_user):
    employee_id = create_user(role="employee", email="erin@test.local")
    with app.app_context():
        employee = _db.session.get(User, employee_id)
        report = PhishingReport(
            reporter_id=employee.id, sender_address="a@evil.example",
            subject="S", message_content="B", attack_type="phishing", status="pending",
        )
        _db.session.add(report)
        _db.session.commit()

        entry = AuditLog(
            user_id=employee.id, user_name=employee.full_name,
            action="report_submitted", report_id=report.id, description="submitted",
        )
        _db.session.add(entry)
        _db.session.commit()

        assert entry.report is report
        assert report.audit_entries == [entry]


def test_quiz_question_and_result(app):
    with app.app_context():
        question = QuizQuestion(
            question="Pick b", option_a="a", option_b="b", option_c="c", option_d="d",
            correct_answer="b",
        )
        _db.session.add(question)
        _db.session.commit()

        assert question.is_correct("b")
        assert question.is_correct("B")
        assert not question.is_correct("a")
        assert not question.is_correct("")
        assert len(question.options()) == 4

        employee = Employee(full_name="Erin", email="quiz@test.local")
        employee.set_password("Password123")
        _db.session.add(employee)
        _db.session.commit()

        result = QuizResult(user_id=employee.id, score=8, total_questions=10)
        _db.session.add(result)
        _db.session.commit()
        assert result.percentage == 80
        assert employee.quiz_results.count() == 1
