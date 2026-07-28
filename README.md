# Secure Login Web App

A Flask-based authentication system demonstrating core web security practices: password hashing, injection-safe database queries, session management, account lockout, and optional two-factor authentication (2FA).

Built as a learning project to practice secure authentication design — not a production-ready auth service.

## Features

- **User registration & login** with input validation (username, email, password strength)
- **Password hashing with bcrypt** — each password gets a unique random salt, so identical passwords never produce identical hashes
- **SQL injection protection** via parameterized queries (no string concatenation into SQL, anywhere)
- **Session management** using Flask's signed session cookies, with a proper logout that clears the session entirely
- **Account lockout** after 5 failed login attempts (15-minute cooldown) to slow down brute-force attempts
- **Optional TOTP-based 2FA** (Google Authenticator / Authy compatible) with QR code setup
- **Generic error messages** on login/registration failures, to avoid leaking which accounts exist

## Tech Stack

- Python 3 / Flask
- SQLite (via `sqlite3`, no ORM — keeps the SQL visible for learning purposes)
- `bcrypt` — password hashing
- `pyotp` + `qrcode` — TOTP 2FA

## Project Structure
```text
secure_login_app/
├── app.py # Routes, session logic, 2FA flow
├── models.py # Database layer — all queries are parameterized
├── validation.py # Input format validation (username/email/password rules)
├── requirements.txt
├── screenshots/
│ ├── registration_page.png
│ ├── login_page.png
│ ├── welcome_page.png
│ ├── qr_page.png
│ └── code_verification_page.png
├── templates/
│ ├── base.html
│ ├── register.html
│ ├── login.html
│ ├── verify_2fa.html
│ ├── setup_2fa.html
│ └── dashboard.html
└── static/
```


## Setup

```bash
git clone <your-repo-url>
cd secure_login_app
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Visit `http://127.0.0.1:5000`. The SQLite database (`app.db`) is created automatically on first run.

### Environment variable (recommended)

The app falls back to a randomly generated session secret if none is set, which is fine for local testing but means sessions won't survive a server restart. For anything beyond local testing, set your own:

```bash
export SECRET_KEY="your-random-secret-here"   # Windows: set SECRET_KEY=...
```

## Security Notes

A few design decisions worth calling out (also commented in the code):

- **Why bcrypt, not plain hashing (e.g. SHA-256):** bcrypt is deliberately slow and includes a per-password salt, which makes both rainbow-table attacks and brute-forcing computationally expensive. A fast general-purpose hash like SHA-256 is the wrong tool for passwords.
- **Why parameterized queries prevent SQL injection:** placeholders (`?`) pass values to the database driver as *data*, never as part of the SQL command string — so malicious input like `' OR '1'='1` is stored/matched as a literal string, not executed as SQL logic.
- **Why login/registration errors are generic:** revealing "that username doesn't exist" vs. "wrong password" lets an attacker enumerate valid accounts one guess at a time.

## Known Limitations / Not Included

This is a learning project, so a few things a production system would need are intentionally left out:
- No HTTPS enforcement (session cookies are visible in plaintext over HTTP — always run behind HTTPS in real deployments)
- No email verification on registration
- No password reset flow
- No rate limiting at the network level (only failed-attempt lockout per account)
- SQLite is fine for learning/demo purposes but isn't meant for concurrent production traffic

## Possible Extensions

- Switch to Argon2 (`argon2-cffi`) instead of bcrypt
- Add `flask-limiter` for IP-based rate limiting
- Add password reset via email token
- Move to PostgreSQL/MySQL for a more production-realistic setup

## License

MIT — feel free to use this for learning purposes.
