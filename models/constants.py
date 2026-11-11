"""Domain constants shared across models, routes, services and templates.

Keeping these values in one module guarantees that validation, badges and
database values always agree.
"""

# Allowed attack types for reported messages
ATTACK_TYPES = {
    "phishing": "Phishing",
    "spear_phishing": "Spear Phishing",
    "smishing": "Smishing",
    "bec": "Business Email Compromise (BEC)",
    "malware": "Malware",
    "credential_theft": "Credential Theft",
    "social_engineering": "Social Engineering",
    "other": "Other",
}

# Lifecycle of a report
STATUSES = {
    "pending": "Pending",
    "under_investigation": "Under Investigation",
    "legitimate": "Legitimate",
    "suspicious": "Suspicious",
    "confirmed_phishing": "Confirmed Phishing",
    "closed": "Closed",
}

# Severity levels assigned by analysts
SEVERITIES = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

# Investigation outcome classification
CLASSIFICATIONS = {
    "confirmed_phishing": "Confirmed Phishing",
    "suspicious": "Suspicious",
    "legitimate": "Legitimate",
    "unresolved": "Unresolved",
}

# Categories for awareness articles
ARTICLE_CATEGORIES = {
    "phishing": "Phishing",
    "social_engineering": "Social Engineering",
    "account_security": "Account Security",
    "safe_browsing": "Safe Browsing",
    "incident_response": "Incident Response",
}

# User roles (single-table inheritance discriminators)
ROLES = ("employee", "analyst", "admin")
ROLE_LABELS = {
    "employee": "Employee",
    "analyst": "Security Analyst",
    "admin": "Administrator",
}
