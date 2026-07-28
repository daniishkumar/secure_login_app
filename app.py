"""
Secure Login Web App
---------------------
Flask app demonstrating: bcrypt password hashing, parameterized SQL
(injection-safe), server-side session management, account lockout
after repeated failed logins, and optional TOTP-based 2FA.

Run:
    pip install -r requirements.txt
    python app.py
Then visit http://127.0.0.1:5000
"""

import os
import secrets
from datetime import datetime, timedelta

import bcrypt
import pyotp
import qrcode
import io
import base64
from flask import Flask, render_template, request, redirect, url_for, session, flash

import models
import validation

app = Flask(__name__)

# SECRET_KEY signs the session cookie. If this leaked or were guessable,
# an attacker could forge session data. In production, load this from an
# environment variable / secrets manager — never hardcode it in source
# control. secrets.token_hex is used here only as a dev-time fallback.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

models.init_db()


# --- Helpers ----------------------------------------------------------------

def hash_password(password: str) -> str:
    # bcrypt automatically generates and embeds a random salt per password,
    # so two users with the same password get completely different hashes —
    # this defeats precomputed "rainbow table" lookups.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def login_required(view_func):
    def wrapper(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper


# --- Routes -------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "username" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Validate everything before touching the database.
        for error in (
            validation.validate_username(username),
            validation.validate_email(email),
            validation.validate_password(password),
        ):
            if error:
                flash(error, "error")
                return render_template("register.html")

        password_hash = hash_password(password)
        created = models.create_user(username, email, password_hash)

        if not created:
            # Deliberately vague — don't reveal whether it was the
            # username or email that collided, since confirming which
            # field exists helps an attacker enumerate real accounts.
            flash("That username or email is already registered.", "error")
            return render_template("register.html")

        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = models.get_user_by_username(username)

        # Check lockout status first.
        if user and user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now() < locked_until:
                minutes_left = int((locked_until - datetime.now()).total_seconds() / 60) + 1
                flash(f"Account locked. Try again in {minutes_left} minute(s).", "error")
                return render_template("login.html")

        # Deliberately identical error message whether the username doesn't
        # exist OR the password is wrong. If these differed, an attacker
        # could use the login form to enumerate which usernames are valid.
        generic_error = "Invalid username or password."

        if not user or not verify_password(password, user["password_hash"]):
            if user:
                attempts = user["failed_attempts"] + 1
                locked_until = None
                if attempts >= MAX_FAILED_ATTEMPTS:
                    locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                    generic_error = f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes."
                models.record_failed_attempt(username, locked_until)
            flash(generic_error, "error")
            return render_template("login.html")

        models.reset_failed_attempts(username)

        # If 2FA is enabled, don't log them in yet — stash identity in a
        # short-lived "pending" session slot and redirect to the TOTP check.
        if user["totp_enabled"]:
            session["pending_2fa_user"] = username
            return redirect(url_for("verify_2fa"))

        session["username"] = username
        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    username = session.get("pending_2fa_user")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user = models.get_user_by_username(username)
        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code, valid_window=1):  # allows 30s clock drift
            session.pop("pending_2fa_user", None)
            session["username"] = username
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid 2FA code.", "error")

    return render_template("verify_2fa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = models.get_user_by_username(session["username"])
    return render_template("dashboard.html", user=user)


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = models.get_user_by_username(session["username"])

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("pending_totp_secret")
        totp = pyotp.TOTP(secret)

        if totp.verify(code, valid_window=1):
            models.set_totp_secret(user["username"], secret)
            session.pop("pending_totp_secret", None)
            flash("Two-factor authentication enabled!", "success")
            return redirect(url_for("dashboard"))
        flash("Incorrect code — scan the QR code again and try the new code.", "error")

    # Generate a new TOTP secret + QR code for the user's authenticator app
    # (Google Authenticator, Authy, etc.) to scan.
    secret = pyotp.random_base32()
    session["pending_totp_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="SecureLoginApp")

    qr = qrcode.make(uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template("setup_2fa.html", qr_base64=qr_base64, secret=secret)


@app.route("/logout")
def logout():
    session.clear()  # wipes the entire session, not just 'username'
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
