# 🛡️ PARS — Phishing Awareness & Reporting System

A complete, working **Flask + SQLite** web application that lets employees report
suspected phishing and social engineering attacks, and gives security staff the
tools to investigate, classify, track and learn from every incident.

Built as a teaching-grade project that demonstrates **Python, Flask, Object-Oriented
Programming, SQLAlchemy ORM, role-based access control, secure authentication,
audit logging, cybersecurity awareness content and automated testing**.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Objectives](#objectives)
3. [Features](#features)
4. [Technologies Used](#technologies-used)
5. [System Architecture](#system-architecture)
6. [Database Design](#database-design)
7. [OOP Concepts Used (and where)](#oop-concepts-used-and-where)
8. [Project Structure](#project-structure)
9. [Installation](#installation)
10. [How to Run](#how-to-run)
11. [Default Accounts](#default-accounts)
12. [How the Reporting Workflow Works](#how-the-reporting-workflow-works)
13. [Security Measures](#security-measures)
14. [Testing](#testing)
15. [Future Improvements](#future-improvements)

---

## Project Overview

Phishing remains the #1 initial-access vector for real-world breaches. PARS gives
an organization two complementary capabilities:

- **Employees** get a one-click way to report suspicious emails, SMS, or messages —
  with the details security needs — plus an Awareness Center and a graded quiz to
  build their instincts.
- **Security analysts** get an investigation dashboard: search/filter across all
  reports, open and investigate individual incidents, add findings and notes,
  assign severity, classify the attack, change status, and close incidents.
  Every important change is recorded in the database (status history + audit log).
- **Administrators** manage users (including analyst accounts), view system-wide
  statistics, and maintain the awareness article library.

## Objectives

- Demonstrate **clean, modular Flask architecture** (models / routes / services /
  templates / static files — never one giant Python file).
- Demonstrate **real OOP**: classes with constructors, encapsulation, inheritance
  (single-table inheritance for the three roles), methods and object relationships.
- Demonstrate **database modelling** with SQLAlchemy ORM and SQLite.
- Demonstrate **secure authentication**: hashed passwords, sessions, role-based
  access control, CSRF protection, input validation, XSS-safe output.
- Demonstrate an **incident lifecycle**: report → investigate → classify → close,
  with a complete audit trail.
- Ship with **tests** and **seed data** so it runs out of the box.

## Features

**Roles & access control**

- Three roles — Employee, Security Analyst, Administrator — with protected routes
  and a role-aware sidebar. Employees cannot reach analyst/admin pages; analysts
  cannot reach admin pages; admins are a superset of analysts for incidents.

**Reporting (employees)**

- Full report form: sender, subject, suspicious URL, message content, date
  received, attack type (Phishing, Spear Phishing, Smishing, BEC, Malware,
  Credential Theft, Social Engineering, Other), optional evidence attachment,
  and comments.
- Server-side validation with friendly per-field errors.
- Personal dashboard with stats and a prominent "Report Suspicious Message" button.
- View own reports and their live status.

**Investigation (analysts)**

- Dashboard with clickable stat cards and CSS-rendered charts (status, attack
  type, severity).
- Search by sender / report ID / attack type / subject; filter by status, severity,
  attack type and date range; pagination.
- Report detail page: full report data, investigation record, findings, timestamped
  analyst notes, classification, severity, status, status history timeline, audit trail.
- Actions: start investigation, save findings, add notes, change severity, classify,
  change status, close incident.
- Incident history page: every status transition across all reports, plus recent
  security events.

**Awareness**

- Awareness Center with articles covering phishing, link inspection, social
  engineering, spear phishing, BEC, smishing, passwords, MFA, safe browsing and
  incident response.
- Admin CRUD for articles (create/edit/delete, all audited).
- 10-question multiple-choice quiz with stored results, percentage score and
  feedback; users can retake and view their history.

**Administration**

- System dashboard: users by role, report totals, quiz stats, recent security events.
- User management: create accounts for any role, change roles, activate/deactivate,
  reset passwords, delete accounts (with safety checks).
- Article management.

## Technologies Used

| Layer | Technology |
| --- | --- |
| Language | Python 3 (3.9+) |
| Web framework | Flask 3 |
| ORM | SQLAlchemy 2 via Flask-SQLAlchemy |
| Database | SQLite (file: `instance/phishing.db`) |
| Authentication | Flask-Login + Werkzeug password hashing (PBKDF2) |
| CSRF protection | Flask-WTF `CSRFProtect` |
| Templates | Jinja2 (auto-escaped, XSS-safe) |
| Front-end | HTML5, CSS3 (responsive), vanilla JavaScript |
| Testing | pytest |
| Config | Environment variables via `python-dotenv` |

## System Architecture

PARS follows the classic Flask layered architecture:

```
Browser / HTML
      │
      ▼
┌────────────────────────────────────────────────────────────┐
│ Routes (blueprints) — HTTP layer, auth, role checks, forms  │
│   routes/auth.py · employee.py · analyst.py · admin.py ·    │
│   awareness.py                                              │
└──────────────────────────────┬─────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────┐
│ Services — business logic & validation                     │
│   report_service · investigation_service · quiz_service ·  │
│   awareness_service · user_service · audit_service ·       │
│   attachment_service                                       │
└──────────────────────────────┬─────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────┐
│ Models (SQLAlchemy ORM) — OOP domain classes               │
│   User / Employee / SecurityAnalyst / Administrator        │
│   PhishingReport / StatusHistory / AuditLog / Investigation│
│   AwarenessArticle / QuizQuestion / QuizResult             │
└──────────────────────────────┬─────────────────────────────┘
                               ▼
                        SQLite database
                        (instance/phishing.db)
```

**Request flow example** — an analyst changes a report's status:

1. `routes/analyst.py` `change_status()` — decorated with `@role_required("analyst", "admin")`.
2. The POST body's CSRF token is verified by `CSRFProtect`.
3. `InvestigationService.set_status(report, actor, new_status)` validates the status.
4. `report.update_status(new_status, changed_by)` (a **method on the model**) records a
   `StatusHistory` row.
5. `AuditService.log_action(...)` writes an `AuditLog` row ("Analyst changed report
   #15 from Pending to Under Investigation.").
6. The template re-renders the detail page with the new state.

## Database Design

```
users (single-table inheritance; role = discriminator)
├── id, full_name, email, password_hash, role, active, created_at
├── 1─N  phishing_reports   (reporter_id)
├── 1─N  investigations     (analyst_id)
├── 1─N  quiz_results       (user_id)
└── 1─N  audit_logs         (user_id, nullable — kept if account is deleted)

phishing_reports
├── id, reporter_id → users.id
├── sender_address, subject, suspicious_link, message_content
├── date_received, attack_type, severity, status
├── comments, attachment_filename, attachment_original_name
├── created_at, updated_at
├── 1─N status_history   (report_id)      — every status transition
├── 1─1 investigation    (report_id)      — analyst workflow record
└── 1─N audit_logs       (report_id)

status_history    id, report_id, previous_status, new_status, changed_by, changed_at
investigations    id, report_id (unique), analyst_id, findings, analyst_notes,
                  classification, started_at, investigated_at
audit_logs        id, user_id, user_name, action, report_id, description, created_at
awareness_articles id, title, category, content, created_at, updated_at
quiz_questions    id, question, option_a..d, correct_answer
quiz_results      id, user_id, score, total_questions, completed_at
```

All relationships are declared on the models with proper foreign keys, so
SQLAlchemy enforces referential integrity.

## OOP Concepts Used (and where)

This is the part a student can defend in an interview. The OOP is not decoration —
every class below is instantiated and used by the running application.

| Concept | Where | Why it matters |
| --- | --- | --- |
| **Classes & objects** | Every model (`PhishingReport`, `Investigation`, `QuizResult`, …) and every service class | The whole domain is modelled as objects with state (rows) and behaviour (methods). |
| **Constructors** | `User` and all models use SQLAlchemy's declarative constructor (`Employee(full_name=…, email=…)`); `ReportValidationError.__init__` carries per-field errors | Objects are created in a controlled way. |
| **Encapsulation** | `User.set_password()/check_password()` hide hashing details; `PhishingReport.update_status()` is the *only* place a status transition is recorded; `Investigation.add_note()` timestamps notes; `AttachmentService.save()` sanitizes filenames | Callers say *what*, not *how*. Passwords, status transitions and file handling cannot be bypassed or done wrong. |
| **Inheritance / polymorphism** | `Employee(User)`, `SecurityAnalyst(User)`, `Administrator(User)` — **single-table inheritance** (`polymorphic_on=role`). `db.session.get(User, id)` returns the correct subclass automatically; `InvestigationService.start()` uses `isinstance(actor, SecurityAnalyst)` to dispatch | One `users` table, zero duplicated auth logic, and role-specific behaviour (`Employee.submit_report`, `SecurityAnalyst.start_investigation`, `Administrator.create_user`). |
| **Methods (behaviour on objects)** | `report.update_status()`, `investigation.add_note()/classify()`, `question.is_correct()`, `result.percentage`, `user.has_role()` | Domain logic lives with the data it operates on. |
| **Relationships between objects** | `report.reporter`, `reporter.reports`, `report.investigation`, `investigation.analyst`, `report.status_history`, `report.audit_entries`, `user.quiz_results` | Navigate the domain naturally: `report.reporter.email`, `analyst.investigations.count()`. |
| **Composition / services** | Routes delegate to service classes (`ReportService`, `InvestigationService`, `AuditService`, …) which coordinate models | Separation of concerns: HTTP layer ≠ business logic ≠ persistence. |

## Project Structure

```
phishing_awareness_system/
│
├── app.py                  # Application factory, extensions wiring, CLI, error handlers
├── config.py               # Configuration from environment variables
├── extensions.py           # Shared db / login_manager / csrf instances
├── requirements.txt
├── README.md
├── .env.example            # Copy to .env and set SECRET_KEY
├── pytest.ini
│
├── models/
│   ├── __init__.py         # Registry so all tables are known to SQLAlchemy
│   ├── constants.py        # Statuses, attack types, severities, roles, categories
│   ├── user.py             # User (base) + Employee / SecurityAnalyst / Administrator
│   ├── report.py           # PhishingReport, StatusHistory, AuditLog
│   ├── investigation.py    # Investigation
│   ├── awareness.py        # AwarenessArticle
│   └── quiz.py             # QuizQuestion, QuizResult
│
├── routes/
│   ├── __init__.py         # role_required decorator + blueprint registration
│   ├── auth.py             # login / register / logout / change-password
│   ├── employee.py         # employee dashboard, submit report, my reports
│   ├── analyst.py          # analyst dashboard, reports, investigation, history
│   ├── admin.py            # admin dashboard, users, articles
│   └── awareness.py        # articles, quiz, quiz results
│
├── services/
│   ├── __init__.py
│   ├── report_service.py       # validation, submission, search, stats
│   ├── investigation_service.py# investigation workflow
│   ├── audit_service.py        # audit trail
│   ├── quiz_service.py         # grading + feedback
│   ├── awareness_service.py    # article CRUD
│   ├── user_service.py         # registration + admin user management
│   └── attachment_service.py   # safe file upload/download
│
├── templates/
│   ├── base.html, macros.html
│   ├── auth/  employee/  analyst/  admin/  awareness/  errors/
│
├── static/
│   ├── css/style.css
│   └── js/main.js
│
├── instance/               # Created at runtime: phishing.db + uploads/
├── seed.py                 # Demo data + default accounts
└── tests/
    ├── conftest.py
    ├── test_auth.py        # registration/login/hashing/access control
    ├── test_reports.py     # submission/validation/investigation/search
    ├── test_models.py      # OOP, inheritance, relationships
    └── test_quiz.py        # quiz grading/storage/feedback
```

## Installation

Requires **Python 3.9+**.

```bash
# 1. (Recommended) create a virtual environment
python -m venv .venv

# 2. activate it
#    Windows (PowerShell):  .venv\Scripts\Activate.ps1
#    Windows (cmd):         .venv\Scripts\activate.bat
#    macOS/Linux:           source .venv/bin/activate

# 3. install dependencies
pip install -r requirements.txt

# 4. create the environment file and set a strong secret key
cp .env.example .env
# then edit .env — generate a key with:
#   python -c "import secrets; print(secrets.token_hex(32))"
```

## How to Run

```bash
# create the database tables
flask --app app init-db

# load demo data (users, reports, articles, quiz questions)
flask --app app seed-db          # or: python seed.py

# start the development server
flask --app app run              # or: python app.py
```

Open **http://127.0.0.1:5000** in your browser.

> `python seed.py --force` wipes and reseeds the database.

## Default Accounts

> ⚠️ **CHANGE THESE PASSWORDS IMMEDIATELY** after your first login
> (sidebar → Change password). The seed data is for demonstration only.

| Role | Email | Password |
| --- | --- | --- |
| Administrator | `admin@pars.local` | `Admin@12345` |
| Security Analyst | `analyst@pars.local` | `Analyst@12345` |
| Employee | `employee@pars.local` | `Employee@12345` |
| Employee | `bob@pars.local` | `Employee@12345` |

New employees can also self-register from the login page (they always start with
the Employee role).

## How the Reporting Workflow Works

1. **Employee** receives a suspicious message and clicks **🚨 Report Suspicious
   Message**.
2. They fill in the form (sender, subject, link, message content, attack type,
   optional evidence). The server validates everything; the suspicious link is
   stored as *plain text* and is never opened, fetched or executed by the system.
3. The report is created with status **Pending**, severity **Low**, and an audit
   entry is recorded.
4. **Analyst** sees it on the dashboard and in the Reports list (search/filter
   available). Opening the report, they can **Start investigation** — the status
   becomes **Under Investigation** and a status-history row is recorded.
5. The analyst adds **findings**, timestamped **notes**, sets **severity**,
   chooses a **classification** (Confirmed Phishing / Suspicious / Legitimate /
   Unresolved) and finally **changes status** or **closes the incident**.
6. Every one of those actions writes an **audit log** entry, so the full story of
   the incident is reconstructable later ("Analyst changed report #15 from Pending
   to Under Investigation.").
7. The **employee** watches the status on their own report page, and the
   **incident history** page lets analysts see all transitions across the org.

## Security Measures

- **Password hashing** — Werkzeug `generate_password_hash` (PBKDF2 with salt).
  Plain-text passwords never touch the database.
- **CSRF protection** — every POST form carries a CSRF token enforced by
  Flask-WTF; tokens expire after 1 hour.
- **Secure sessions** — Flask-Login with `session_protection="strong"`, HTTPOnly
  and SameSite=Lax cookies, `SESSION_COOKIE_HTTPONLY`.
- **Role-based access control** — the `role_required` decorator on every protected
  route; anonymous users are redirected, wrong roles get 403.
- **SQL injection protection** — all queries go through the SQLAlchemy ORM with
  bound parameters; no raw SQL in the application.
- **XSS protection** — Jinja2 autoescaping everywhere; user-submitted report
  content and article text are rendered through an `nl2br` filter that escapes
  first and only then inserts `<br>`; suspicious links are rendered as escaped
  text (never clickable) with a copy button.
- **Safe handling of submitted links** — only `http`/`https` schemes are
  accepted; links are never opened, fetched or executed by the system.
- **File upload restrictions** — allow-list of extensions (images/PDF/text),
  2 MB size cap (`MAX_CONTENT_LENGTH`), files renamed to random UUIDs, original
  names sanitized, served with `Content-Disposition: attachment` (download, not
  render), and path traversal is blocked when resolving downloads.
- **Input validation** — every form is validated server-side (report form, quiz,
  registration, user management, article CRUD).
- **Audit trail** — user management and incident actions are logged; accounts can
  only be deleted when no dependent records exist, and the audit trail survives.
- **Environment-based configuration** — `SECRET_KEY` and `DATABASE_URL` come from
  environment variables (`.env`); sensible dev defaults are documented.

## Testing

```bash
pip install -r requirements.txt
python -m pytest -v
```

The suite (43 tests) covers:

- **test_auth.py** — registration, duplicate email, weak passwords, login
  success/failure, logout, deactivated accounts, password hashing, role-based
  access (employee→analyst 403, analyst→admin 403, anonymous→login redirect),
  password change.
- **test_reports.py** — submission flow + audit, required-field validation,
  rejection of non-http links, invalid attack types, employee privacy (404 on
  others' reports), status updates recording history, classification/severity,
  full investigate→close flow, search & filters, dashboard rendering,
  attachment upload and extension restrictions.
- **test_models.py** — single-table inheritance (correct subclasses returned),
  password roundtrip/salting, `Administrator.create_user` factory, report↔user
  relationships, `Employee.submit_report`, status-history behaviour, investigation
  relationships and notes, audit relationships, quiz question/result behaviour.
- **test_quiz.py** — grading, feedback thresholds, result persistence, auth
  requirement, privacy of results, history page.

Tests use a temporary SQLite database and have CSRF disabled — they never touch
the real `instance/phishing.db`.

## Future Improvements
## Future Improvements
- Auto-fetch current phishing trends and generate new awareness articles/quiz questions automatically
- Email-based password reset instead of admin-only resets.
- Indicator of compromise (IoC) extraction from reports (domains, hashes, IPs).
- Bulk actions on reports (export CSV, mark multiple as phishing).
- Integration with mail servers ("Report to PARS" button forwarding the raw
  message/EML).
- Scheduled phishing simulation campaigns with per-team statistics.
- Rate limiting and account lockout after repeated failed logins.
- Replace the demo quiz with a question bank and randomized quizzes.
- Deploy with Gunicorn/uWSGI behind HTTPS, PostgreSQL, and Docker.
