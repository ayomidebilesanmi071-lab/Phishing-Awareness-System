"""Database seed script.

Creates demo users, sample reports with full history, awareness articles and
quiz questions. Safe to run repeatedly: it only seeds when the users table is
empty (or with --force to wipe and reseed).

Usage:
    python seed.py            # seed an empty database
    python seed.py --force    # drop everything and reseed
    flask --app app seed-db   # equivalent of python seed.py
"""

import sys
from datetime import datetime, timedelta

from app import create_app
from extensions import db
from models.awareness import AwarenessArticle
from models.investigation import Investigation
from models.quiz import QuizQuestion, QuizResult
from models.report import AuditLog, PhishingReport, StatusHistory
from models.user import Administrator, Employee, SecurityAnalyst, User

# --------------------------------------------------------------------------- #
# Default accounts - CHANGE THESE IMMEDIATELY after first login (see README).
# --------------------------------------------------------------------------- #
DEFAULT_ACCOUNTS = [
    ("Alice Administrator", "admin@pars.local", "Admin@12345", "admin"),
    ("Sam Security",        "analyst@pars.local", "Analyst@12345", "analyst"),
    ("Erin Employee",       "employee@pars.local", "Employee@12345", "employee"),
    ("Bob Brown",           "bob@pars.local", "Employee@12345", "employee"),
]

ARTICLES = [
    ("What Is Phishing?",
     "phishing",
     "Phishing is a type of social engineering attack in which criminals impersonate "
     "a trusted person or organization to trick you into revealing sensitive "
     "information such as passwords, credit card numbers or login credentials.\n\n"
     "Phishing usually arrives by email, but it can also come through SMS (smishing), "
     "phone calls (vishing) or fake websites. The goal is always the same: make you act "
     "quickly, bypass your judgment, and hand over data or money.\n\n"
     "Remember: legitimate companies never ask you to send passwords, PINs or payment "
     "details by email. If a message pressures you to act immediately, slow down and verify."),
    ("How to Identify Phishing Emails",
     "phishing",
     "Look for these warning signs in any unexpected email:\n\n"
     "1. Urgency - messages claiming your account will be locked or a payment is overdue.\n"
     "2. Mismatched sender - the display name looks right but the address is a random domain.\n"
     "3. Generic greetings - 'Dear customer' instead of your real name.\n"
     "4. Grammar and spelling errors that a real organization would not publish.\n"
     "5. Requests for credentials, MFA codes or money transfers.\n"
     "6. Suspicious attachments or links that do not match the claimed destination.\n\n"
     "When in doubt, do not click. Verify the sender through a known channel and report "
     "the message to your security team."),
    ("How to Identify Suspicious Links",
     "phishing",
     "Attackers often hide malicious destinations behind links that look legitimate. "
     "Before clicking, hover over the link and read the real destination shown by your "
     "browser or mail client.\n\n"
     "Red flags include: misspelled domains (amaz0n.com, paypa1.com), extra subdomains "
     "(login.secure-verify.example.com), URL shorteners hiding the target, and links that "
     "do not match the sender's organization.\n\n"
     "Never trust a link that asks you to log in from an email. Type the known address of "
     "the service directly into your browser instead, and report anything suspicious "
     "through PARS."),
    ("Social Engineering: The Human Factor",
     "social_engineering",
     "Social engineering is the art of manipulating people into breaking security "
     "procedures. Attackers exploit trust, authority, fear, urgency and curiosity rather "
     "than technical vulnerabilities.\n\n"
     "Common techniques: impersonating executives or IT staff, pretexting (inventing a "
     "plausible reason to ask for information), baiting with free items, and tailgating "
     "into restricted areas.\n\n"
     "Your best defense is to verify identity through an independent channel, question "
     "unexpected requests, and remember that legitimate staff will never mind you "
     "double-checking."),
    ("Spear Phishing: When Attacks Are Personal",
     "social_engineering",
     "Spear phishing is a targeted form of phishing. Instead of sending thousands of "
     "generic emails, the attacker researches a specific person or company and crafts a "
     "message that references real projects, colleagues or recent events.\n\n"
     "Because the message looks personal and credible, the recipient is more likely to "
     "click or reply. Attackers gather the details from social media, company websites "
     "and public directories.\n\n"
     "Be especially careful with messages that reference internal information but ask "
     "you to do something unusual, such as changing payment details or sharing "
     "credentials. Confirm through a known channel before acting."),
    ("Business Email Compromise (BEC)",
     "social_engineering",
     "Business Email Compromise (BEC) is a scam in which attackers compromise or "
     "impersonate a legitimate business email account - often a CEO, CFO or supplier - "
     "to authorize fraudulent wire transfers or steal sensitive data.\n\n"
     "Classic BEC patterns: a 'CEO' urgently asks finance to pay an invoice, a 'vendor' "
     "asks to change their bank details, or an 'attorney' requests gift cards.\n\n"
     "Financial requests deserve extra verification: call the requester on a known phone "
     "number, confirm through a second channel, and never trust a change of payment "
     "details sent by email alone."),
    ("Smishing and Vishing",
     "social_engineering",
     "Smishing is phishing delivered by SMS text message, and vishing is phishing over "
     "the phone. Both play on urgency: 'Your package is held - confirm your card now', "
     "or 'This is your bank's fraud team - verify your account immediately'.\n\n"
     "Never click links in unexpected text messages or give out passwords, PINs or "
     "one-time codes over the phone. If a caller claims to be from your bank, hang up "
     "and call the number on the back of your card.\n\n"
     "Report smishing messages to your security team and, if safe, forward them to your "
     "mobile provider's abuse number."),
    ("Password Security Best Practices",
     "account_security",
     "Strong, unique passwords are a first line of defense. Use a passphrase of at "
     "least 12-16 characters that combines unrelated words, and never reuse the same "
     "password across sites.\n\n"
     "A password manager removes the burden of remembering dozens of passwords and "
     "helps you spot fake login pages. Never share passwords with anyone - IT staff "
     "will never ask for yours.\n\n"
     "If you suspect a password has been compromised, change it immediately and enable "
     "multi-factor authentication on the account."),
    ("Multi-Factor Authentication (MFA)",
     "account_security",
     "Multi-factor authentication (MFA) requires two or more proofs of identity: "
     "something you know (password), something you have (phone, security key) and "
     "something you are (fingerprint, face).\n\n"
     "MFA is one of the most effective defenses against credential theft. Even if an "
     "attacker steals your password, they cannot log in without the second factor.\n\n"
     "Prefer authenticator apps or hardware keys over SMS codes when possible, and "
     "never share one-time codes with anyone - a real service will never ask you to "
     "read your code back over the phone."),
    ("Safe Browsing Habits",
     "safe_browsing",
     "Safe browsing starts before you click. Keep your browser and operating system "
     "updated, use the browser's built-in protection features, and check the padlock "
     "and full domain in the address bar before entering credentials.\n\n"
     "Avoid downloading software from pop-ups or unknown sites, and be wary of 'free' "
     "offers that ask for personal information.\n\n"
     "If a page looks wrong - strange URL, unusual layout, aggressive pop-ups - close "
     "it and navigate to the official site directly."),
    ("What to Do After Clicking a Suspicious Link",
     "incident_response",
     "If you clicked a suspicious link or opened an unexpected attachment, stay calm "
     "and act quickly:\n\n"
     "1. Disconnect from the network (turn off Wi-Fi or unplug the cable) if you "
     "entered credentials.\n"
     "2. Do NOT enter more information, and do not forward the message to others.\n"
     "3. Change the passwords of any accounts you may have exposed, and enable MFA.\n"
     "4. Report the incident immediately through PARS and tell your security team "
     "what you clicked and what you entered.\n\n"
     "Reporting fast limits the damage. You will never be penalized for reporting - "
     "the danger is staying silent."),
]

QUIZ_QUESTIONS = [
    ("What is phishing?",
     "A legitimate marketing technique used by companies",
     "A fraudulent attempt to obtain sensitive information by impersonating a trusted entity",
     "A type of computer virus that deletes files",
     "A spam email that is annoying but harmless",
     "b"),
    ("Which of these is a common warning sign of a phishing email?",
     "A personalized greeting using your full name",
     "A calm, detailed explanation of a routine update",
     "An urgent demand to verify your password immediately",
     "The sender's address exactly matching the official domain",
     "c"),
    ("What should you do to check a link's real destination before clicking it?",
     "Copy the link into a search engine",
     "Hover over it and inspect the URL shown by the browser",
     "Open it in a private window to stay safe",
     "Ask a colleague to click it first",
     "b"),
    ("What does BEC stand for?",
     "Business Email Compromise",
     "Browser Extension Control",
     "Backup Encryption Certificate",
     "Basic Email Configuration",
     "a"),
    ("Smishing attacks arrive through which channel?",
     "Fax messages",
     "Phone calls only",
     "Text (SMS) messages",
     "Social media posts only",
     "c"),
    ("What is the strongest defense against credential theft?",
     "Using the same strong password everywhere",
     "Writing passwords in a notebook",
     "Multi-factor authentication (MFA)",
     "Changing passwords once a year",
     "c"),
    ("A message from 'IT Support' asks you to email them your password to fix an issue. What should you do?",
     "Send the password immediately - it is IT",
     "Reply asking which system needs the password",
     "Refuse to share it and report the message as suspicious",
     "Send a different password you no longer use",
     "c"),
    ("What should you do first after entering credentials on a suspicious site?",
     "Nothing - the site looked legitimate",
     "Close the browser and hope for the best",
     "Change the affected passwords, enable MFA and report the incident",
     "Forward the link to coworkers to warn them",
     "c"),
    ("Which statement about legitimate organizations is true?",
     "They may ask for your password if you call them",
     "They never ask for passwords or MFA codes by email",
     "They will lock your account if you do not reply in 10 minutes",
     "They send password reset links from random domains",
     "b"),
    ("How does spear phishing differ from regular phishing?",
     "It only targets mobile devices",
     "It uses malware instead of deception",
     "It is personalized and targets specific individuals or organizations",
     "It is always sent by fax",
     "c"),
]

# --------------------------------------------------------------------------- #
# Sample reports: (reporter_idx, sender, subject, link, content, attack_type,
#                 severity, status, days_ago, comments)
# --------------------------------------------------------------------------- #
SAMPLE_REPORTS = [
    (0, "security@microsoft-verify.com", "IMPORTANT: Verify your Microsoft 365 password",
     "https://microsoft-verify.com/secure/login",
     "Hello, your Microsoft 365 mailbox will be suspended within 24 hours unless you verify "
     "your password by clicking the link below. This is a final warning.",
     "phishing", "high", "confirmed_phishing", 12,
     "I did not click the link. The sender address looks nothing like our real tenant."),
    (0, "noreply@ups-delivery.info", "Your package is waiting - confirm delivery now",
     "http://ups-tracking.info/confirm?id=8841",
     "Your parcel could not be delivered. Confirm your address and pay a small redelivery fee "
     "using the link. Failure to act will return the parcel to sender.",
     "phishing", "medium", "suspicious", 9, None),
    (1, "accounts@vendorpay.net", "Invoice #8841 overdue - remit payment",
     None,
     "Attached is invoice 8841 for $12,400. Payment is now 30 days overdue. Please remit "
     "immediately or our collections team will be engaged.",
     "bec", "critical", "confirmed_phishing", 8,
     "We have no record of this vendor or invoice. The attachment would not open."),
    (0, "ceo@pars-company.com", "URGENT: Confidential wire transfer required today",
     None,
     "I am in a meeting and cannot take calls. Please arrange a same-day wire transfer of "
     "$8,900 to the account below and reply once done. Keep this confidential.",
     "social_engineering", "high", "under_investigation", 3,
     "The address looks like our CEO's but the reply-to is different."),
    (1, "8827731@msg.giftwin.info", "Congratulations! You have won a $500 gift card",
     "https://giftwin.info/claim",
     "Your phone number was selected. Claim your $500 gift card before midnight by entering "
     "your bank details on the link.",
     "smishing", "low", "pending", 1, None),
    (0, "helpdesk@pars-company.com", "IT Helpdesk: Reset your password now",
     "https://pars-company-verify.net/reset",
     "Our records show your account was involved in a security incident. Click the link to "
     "reset your password within 1 hour or your account will be locked.",
     "credential_theft", "high", "under_investigation", 5,
     "Looks similar to our helpdesk but the domain is wrong."),
    (1, "newsletter@pars-company.com", "Quarterly company newsletter - Q3",
     "https://news.pars-company.com/q3",
     "Read the latest company news, team updates and the security awareness corner in this "
     "quarter's newsletter.",
     "other", "low", "legitimate", 6, "This is a normal internal newsletter."),
    (1, "promo@freeantivirus4u.net", "Free antivirus upgrade - 90% of users already updated",
     "http://freeantivirus4u.net/download",
     "Your antivirus license expires soon. Download the free upgrade now to stay protected "
     "against the latest threats.",
     "malware", "medium", "closed", 15,
     "I did not download anything. Domain is not our software vendor."),
    (0, "conference@cybersummit-2025.org", "Speaking invitation: CyberSummit 2025",
     "https://cybersummit-2025.org/register/team",
     "We would like to invite a member of your security team to speak at CyberSummit 2025. "
     "Register with your work email to receive the agenda.",
     "spear_phishing", "medium", "pending", 2, None),
    (0, "payroll@pars-company.com", "Update your payroll details (new form)",
     "https://pars-payroll-portal.com/login",
     "We migrated to a new payroll portal. Click here to update your banking details and "
     "avoid a delay in your next salary payment.",
     "credential_theft", "high", "suspicious", 4, "The portal domain is not the one HR announced."),
]

# Which sample reports get an investigation record (index -> chain).
INVESTIGATED = {
    0: {"findings": "Link resolves to a look-alike Microsoft login page. Domain registered 6 days ago. "
                    "Sender domain has no SPF/DKIM records. Reported to the external threat feed.",
        "notes": "[2025-08-02 09:15] Sam Security: Started tracing the landing page.\n"
                 "[2025-08-02 14:40] Sam Security: Landing page harvests credentials via a fake Azure login.",
        "classification": "confirmed_phishing"},
    2: {"findings": "Attachment contains a macro-laden invoice. Sender domain flagged in two threat "
                    "intelligence feeds. Wire request matches known BEC playbook.",
        "notes": "[2025-08-10 10:05] Sam Security: Vendor does not exist in the supplier database.",
        "classification": "confirmed_phishing"},
    1: {"findings": "Tracking link redirects to a credential capture page. URL blocked at the gateway.",
        "notes": "[2025-08-09 16:20] Sam Security: Waiting on takedown of the domain.",
        "classification": "suspicious"},
    9: {"findings": "Login portal mimics the HR announcement. TLS certificate is self-signed.",
        "notes": "[2025-08-14 11:00] Sam Security: Advised employees; domain added to blocklist.",
        "classification": "suspicious"},
}


def _make_user(full_name, email, password, role):
    user_class = {"admin": Administrator, "analyst": SecurityAnalyst, "employee": Employee}[role]
    user = user_class(full_name=full_name, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    return user


def _seed_users():
    for full_name, email, password, role in DEFAULT_ACCOUNTS:
        _make_user(full_name, email, password, role)


def _seed_reports():
    now = datetime.utcnow()
    employees = Employee.query.order_by(Employee.id).all()
    analyst = SecurityAnalyst.query.first()

    for idx, (reporter_idx, sender, subject, link, content, attack_type,
              severity, status, days_ago, comments) in enumerate(SAMPLE_REPORTS, start=1):
        reporter = employees[reporter_idx]
        created = now - timedelta(days=days_ago, hours=2)
        report = PhishingReport(
            reporter_id=reporter.id,
            sender_address=sender,
            subject=subject,
            suspicious_link=link,
            message_content=content,
            attack_type=attack_type,
            severity=severity,
            status=status,
            comments=comments,
            date_received=created.date(),
            created_at=created,
        )
        db.session.add(report)
        db.session.flush()

        db.session.add(AuditLog(
            user_id=reporter.id, user_name=reporter.full_name,
            action="report_submitted", report_id=report.id,
            description=f"{reporter.full_name} submitted report #{report.id} ({report.attack_type_label}).",
            created_at=created,
        ))

        # Build a realistic status history ending at the current status.
        chain = ["pending"]
        if status in ("under_investigation", "suspicious", "confirmed_phishing", "closed"):
            chain.append("under_investigation")
        if status in ("suspicious", "confirmed_phishing", "closed"):
            chain.append("suspicious" if status == "suspicious" else "confirmed_phishing")
        if status == "legitimate":
            chain.append("legitimate")
        if status == "closed" and "confirmed_phishing" not in chain:
            chain.append("confirmed_phishing")
        if status == "closed":
            chain.append("closed")

        # StatusHistory rows: pending -> ... -> current status.
        for prev, nxt in zip(chain[:-1], chain[1:]):
            db.session.add(StatusHistory(
                report_id=report.id, previous_status=prev, new_status=nxt,
                changed_by=analyst.full_name,
                changed_at=now - timedelta(days=days_ago, hours=1),
            ))
            db.session.add(AuditLog(
                user_id=analyst.id, user_name=analyst.full_name,
                action="status_change", report_id=report.id,
                description=f"{analyst.full_name} changed report #{report.id} from "
                            f"{prev.replace('_', ' ').title()} to {nxt.replace('_', ' ').title()}.",
                created_at=now - timedelta(days=days_ago, hours=1),
            ))

        # Investigation records for selected reports.
        if idx - 1 in INVESTIGATED:
            data = INVESTIGATED[idx - 1]
            db.session.add(Investigation(
                report_id=report.id, analyst_id=analyst.id,
                findings=data["findings"], analyst_notes=data["notes"],
                classification=data["classification"],
                started_at=now - timedelta(days=days_ago, hours=1),
            ))


def _seed_articles():
    for title, category, content in ARTICLES:
        db.session.add(AwarenessArticle(title=title, category=category, content=content))


def _seed_quiz():
    for question, a, b, c, d, correct in QUIZ_QUESTIONS:
        db.session.add(QuizQuestion(
            question=question, option_a=a, option_b=b, option_c=c, option_d=d,
            correct_answer=correct,
        ))


def _seed_quiz_results():
    now = datetime.utcnow()
    employees = Employee.query.order_by(Employee.id).all()
    db.session.add(QuizResult(user_id=employees[0].id, score=8, total_questions=10,
                              completed_at=now - timedelta(days=3)))
    db.session.add(QuizResult(user_id=employees[0].id, score=6, total_questions=10,
                              completed_at=now - timedelta(days=1)))
    db.session.add(QuizResult(user_id=employees[1].id, score=9, total_questions=10,
                              completed_at=now - timedelta(days=2)))


def seed(force=False):
    app = create_app()
    with app.app_context():
        db.create_all()

        if User.query.count() > 0 and not force:
            print("Database already contains data. Use --force to wipe and reseed.")
            return

        if force:
            print("Wiping existing data...")
            db.drop_all()
            db.create_all()

        _seed_users()
        _seed_reports()
        _seed_articles()
        _seed_quiz()
        _seed_quiz_results()
        db.session.commit()

        print("=" * 62)
        print("PARS database seeded successfully.")
        print("=" * 62)
        print("Default accounts - CHANGE THESE PASSWORDS IMMEDIATELY:")
        print(f"  {'ROLE':<10} {'EMAIL':<24} PASSWORD")
        for full_name, email, password, role in DEFAULT_ACCOUNTS:
            print(f"  {role:<10} {email:<24} {password}")
        print("=" * 62)


if __name__ == "__main__":
    seed(force="--force" in sys.argv)
