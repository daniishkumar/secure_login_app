"""
Input validation.

Note: this validates FORMAT (is it a plausible username/email/password),
which is a UX/data-quality concern. It's NOT what stops SQL injection —
that's handled entirely by parameterized queries in models.py. A common
misconception is "sanitize the input and you're safe from injection" —
in reality, parameterization makes the input's content irrelevant to
SQL structure, so even a value that fails validation couldn't break
a query even if it slipped through.
"""

import re

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_username(username: str) -> str | None:
    if not USERNAME_RE.match(username):
        return "Username must be 3-20 characters: letters, numbers, underscore only."
    return None


def validate_email(email: str) -> str | None:
    if not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    return None


def validate_password(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit."
    return None
