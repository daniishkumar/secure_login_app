"""
Database layer.

KEY SECURITY IDEA: every query here uses '?' placeholders and passes
values as a separate tuple argument — never f-strings or string
concatenation to build SQL. This is what actually prevents SQL
injection: the database driver treats the placeholder values purely
as DATA, never as part of the SQL command itself, no matter what
characters they contain (e.g. a username like "'; DROP TABLE users;--"
is just stored as a literal string, not executed).
"""

import sqlite3
from contextlib import contextmanager

DB_PATH = "app.db"


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            )
        """)


def create_user(username: str, email: str, password_hash: str) -> bool:
    """Returns False if username/email already exists."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),  # <-- data, never concatenated into SQL
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_user_by_username(username: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None


def record_failed_attempt(username: str, locked_until: str | None):
    with get_db() as conn:
        if locked_until:
            conn.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = ? WHERE username = ?",
                (locked_until, username),
            )
        else:
            conn.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?",
                (username,),
            )


def reset_failed_attempts(username: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
            (username,),
        )


def set_totp_secret(username: str, secret: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE username = ?",
            (secret, username),
        )
