# CloudMail

Flask + AWS SES email sending MVP: signup/login, compose (To/CC/BCC), drafts and sent history.

## Local setup

1. `python -m venv .venv`
2. Activate with `.venv\Scripts\Activate.ps1` (PowerShell) or `source .venv/bin/activate` (Linux).
3. `pip install -r requirements.txt`
4. Copy `.env.example` to `.env`, and set `SECRET_KEY` using `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
5. Run `python app.py` and visit http://127.0.0.1:5000.

## AWS SES

Verify a domain identity in your chosen AWS Region; publish DKIM DNS records and configure SPF and DMARC. Request SES production access; sandbox recipients generally must be verified. Configure `SES_FROM_EMAIL` and `AWS_REGION`. Attach an IAM role to EC2 with `ses:SendEmail` permission scoped to the verified identity. Never commit AWS keys. For deployment use PostgreSQL in `DATABASE_URL`, `COOKIE_SECURE=true`, and Gunicorn behind Nginx with HTTPS.

## Limitations before public production

This is a starter MVP, not production hardened. SES sends from one verified identity, not from each user's Gmail address. SES acceptance is not guaranteed delivery. Inbox, attachments, email verification, password reset, login and send rate limiting, abuse prevention, background jobs, migrations, delivery/bounce event processing, and automated tests are not yet implemented. Do not enable public signup until those protections are in place.
