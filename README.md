# Secure Coding Review

This repository contains a small Flask application that demonstrates common secure-coding concepts for authentication workflows.

## Project Overview

The app in `Secure_Coding_Review.py` implements:

- User registration with password hashing (`werkzeug.security`)
- User login with rate limiting (`flask-limiter`)
- Basic 2FA/OTP flow (`pyotp`) and email delivery placeholder (`smtplib`)
- Session-based access control for protected routes
- Security headers via `flask-talisman`
- Password reset token generation
- Basic secure file upload checks
- User activity logging
- SQLite-backed persistence (`users.db`)

## Repository Structure

- `Secure_Coding_Review.py` — main Flask application

## Requirements

Install Python dependencies:

```bash
pip install flask werkzeug flask-limiter flask-talisman pyotp
```

## Running the Application

```bash
export SECRET_KEY="replace-with-a-strong-secret"
python Secure_Coding_Review.py
```

## Security Notes

This is a review/demo project and includes placeholder values that should be replaced before any real deployment, such as:

- SMTP host/credentials in `send_otp`
- Static TOTP secret (`base32secret3232`)
- Incomplete password reset and upload validation flows

## Testing and Linting

No automated test suite or lint configuration is currently present in the repository.
