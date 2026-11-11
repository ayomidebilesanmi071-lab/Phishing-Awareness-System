"""Report lifecycle tests: submission, validation, investigation, search."""

import os
from io import BytesIO

from extensions import db as _db
from models.report import AuditLog, PhishingReport, StatusHistory


def _valid_payload():
    return {
        "sender_address": "attacker@evil.example",
        "subject": "Verify your mailbox",
        "suspicious_link": "https://evil.example/login",
        "message_content": "Your mailbox will be suspended unless you verify now.",
        "attack_type": "phishing",
        "date_received": "2025-01-01",
        "comments": "I was not expecting this email.",
    }


def test_employee_submits_report(client, create_user, login, app):
    reporter = create_user(role="employee", email="erin@test.local")
    login("erin@test.local")

    response = client.post("/employee/report/new", data=_valid_payload())
    assert response.status_code == 302
    assert "/employee/reports/" in response.headers["Location"]

    with app.app_context():
        report = PhishingReport.query.first()
        assert report is not None
        assert report.reporter_id == reporter
        assert report.status == "pending"
        assert report.attack_type == "phishing"
        assert report.subject == "Verify your mailbox"
        # Submission is audited.
        assert AuditLog.query.filter_by(action="report_submitted", report_id=report.id).count() == 1


def test_submission_requires_fields(client, create_user, login):
    create_user(role="employee", email="erin@test.local")
    login("erin@test.local")
    payload = _valid_payload()
    payload["subject"] = ""
    response = client.post("/employee/report/new", data=payload)
    assert response.status_code == 400
    assert b"Subject is required" in response.data


def test_submission_rejects_non_http_links(client, create_user, login):
    create_user(role="employee", email="erin@test.local")
    login("erin@test.local")
    payload = _valid_payload()
    payload["suspicious_link"] = "javascript:alert(1)"
    response = client.post("/employee/report/new", data=payload)
    assert response.status_code == 400
    assert b"valid http(s) URL" in response.data


def test_submission_rejects_invalid_attack_type(client, create_user, login):
    create_user(role="employee", email="erin@test.local")
    login("erin@test.local")
    payload = _valid_payload()
    payload["attack_type"] = "not-a-real-type"
    response = client.post("/employee/report/new", data=payload)
    assert response.status_code == 400
    assert b"valid attack type" in response.data


def test_employee_dashboard_shows_stats(client, create_user, login, make_report):
    reporter = create_user(role="employee", email="erin@test.local")
    make_report(reporter_id=reporter, subject="First one")
    make_report(reporter_id=reporter, subject="Second one")
    login("erin@test.local")
    response = client.get("/employee/")
    assert response.status_code == 200
    assert b"First one" in response.data
    assert b"Second one" in response.data


def test_employee_cannot_see_other_users_report(client, create_user, login, make_report):
    create_user(role="employee", email="bob@test.local")
    other = create_user(role="employee", email="erin@test.local")
    report_id = make_report(reporter_id=other, subject="Erin's private report")
    login("bob@test.local")
    response = client.get(f"/employee/reports/{report_id}")
    assert response.status_code == 404


def test_analyst_status_update_records_history(client, create_user, login, make_report, get_report, app):
    reporter = create_user(role="employee", email="erin@test.local")
    analyst = create_user(role="analyst", email="sam@test.local")
    report_id = make_report(reporter_id=reporter)

    login("sam@test.local")
    response = client.post(f"/analyst/reports/{report_id}/status", data={"status": "under_investigation"})
    assert response.status_code == 302

    with app.app_context():
        report = _db.session.get(PhishingReport, report_id)
        assert report.status == "under_investigation"
        history = StatusHistory.query.filter_by(report_id=report_id).all()
        assert len(history) == 1
        assert history[0].previous_status == "pending"
        assert history[0].new_status == "under_investigation"
        assert AuditLog.query.filter_by(action="status_change", report_id=report_id).count() == 1


def test_analyst_classification_and_severity(client, create_user, login, make_report, app):
    reporter = create_user(role="employee", email="erin@test.local")
    analyst = create_user(role="analyst", email="sam@test.local")
    report_id = make_report(reporter_id=reporter)

    login("sam@test.local")
    client.post(f"/analyst/reports/{report_id}/severity", data={"severity": "high"})
    client.post(f"/analyst/reports/{report_id}/classification", data={"classification": "confirmed_phishing"})

    with app.app_context():
        report = _db.session.get(PhishingReport, report_id)
        assert report.severity == "high"
        assert report.investigation is not None
        assert report.investigation.classification == "confirmed_phishing"
        assert report.status == "under_investigation"  # auto-created investigation moves it
        assert AuditLog.query.filter_by(action="classification", report_id=report_id).count() == 1


def test_analyst_can_investigate_and_close(client, create_user, login, make_report, app):
    reporter = create_user(role="employee", email="erin@test.local")
    analyst = create_user(role="analyst", email="sam@test.local")
    report_id = make_report(reporter_id=reporter)

    login("sam@test.local")
    client.post(f"/analyst/reports/{report_id}/investigate")
    client.post(f"/analyst/reports/{report_id}/findings", data={"findings": "Domain recently registered; fake login page."})
    client.post(f"/analyst/reports/{report_id}/notes", data={"note": "Blocked at the gateway."})
    client.post(f"/analyst/reports/{report_id}/close", data={"closing_note": "Domain takedown requested."})

    with app.app_context():
        report = _db.session.get(PhishingReport, report_id)
        assert report.status == "closed"
        assert report.investigation.findings == "Domain recently registered; fake login page."
        assert "Blocked at the gateway." in report.investigation.analyst_notes
        assert AuditLog.query.filter_by(action="report_closed", report_id=report_id).count() == 1


def test_analyst_search_and_filter(client, create_user, login, make_report):
    reporter = create_user(role="employee", email="erin@test.local")
    analyst = create_user(role="analyst", email="sam@test.local")
    make_report(reporter_id=reporter, subject="Package delivery scam", status="pending", attack_type="phishing")
    make_report(reporter_id=reporter, subject="CEO wire transfer", status="confirmed_phishing", attack_type="bec")

    login("sam@test.local")

    # Filter by status
    response = client.get("/analyst/reports?status=pending")
    assert b"Package delivery scam" in response.data
    assert b"CEO wire transfer" not in response.data

    # Search by attack type
    response = client.get("/analyst/reports?q=bec")
    assert b"CEO wire transfer" in response.data
    assert b"Package delivery scam" not in response.data

    # Search by report ID
    response = client.get("/analyst/reports?q=1")
    assert response.status_code == 200


def test_report_detail_shows_all_fields(client, create_user, login, make_report, app):
    reporter = create_user(role="employee", email="erin@test.local", name="Erin Employee")
    analyst = create_user(role="analyst", email="sam@test.local")
    report_id = make_report(reporter_id=reporter, sender_address="scammer@fake.example", subject="URGENT invoice")

    login("sam@test.local")
    response = client.get(f"/analyst/reports/{report_id}")
    assert response.status_code == 200
    body = response.data
    assert b"#%d" % report_id in body
    assert b"scammer@fake.example" in body
    assert b"URGENT invoice" in body
    assert b"Erin Employee" in body


def test_attachment_upload_and_restriction(client, create_user, login, app):
    reporter = create_user(role="employee", email="erin@test.local")
    login("erin@test.local")

    payload = _valid_payload()
    payload["attachment"] = (BytesIO(b"evidence contents"), "evidence.txt")
    response = client.post("/employee/report/new", data=payload, content_type="multipart/form-data")
    assert response.status_code == 302

    with app.app_context():
        report = PhishingReport.query.first()
        assert report.attachment_filename is not None
        assert report.attachment_original_name == "evidence.txt"
        stored_path = os.path.join(app.config["UPLOAD_FOLDER"], report.attachment_filename)
        assert os.path.isfile(stored_path)
        with open(stored_path, "rb") as fh:
            assert fh.read() == b"evidence contents"


def test_attachment_rejects_disallowed_extension(client, create_user, login):
    create_user(role="employee", email="erin@test.local")
    login("erin@test.local")

    payload = _valid_payload()
    payload["attachment"] = (BytesIO(b"MZ...."), "malware.exe")
    response = client.post("/employee/report/new", data=payload, content_type="multipart/form-data")
    assert response.status_code == 400
    assert b"not allowed" in response.data


def test_analyst_dashboard_renders(client, create_user, login, make_report):
    reporter = create_user(role="employee", email="erin@test.local")
    analyst = create_user(role="analyst", email="sam@test.local")
    make_report(reporter_id=reporter, subject="Sample incident", status="confirmed_phishing", severity="high")

    login("sam@test.local")
    response = client.get("/analyst/")
    assert response.status_code == 200
    assert b"Total reports" in response.data
    assert b"Sample incident" in response.data
