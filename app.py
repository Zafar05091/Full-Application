import os
import re
from datetime import datetime, timezone
from email.utils import parseaddr

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, url_for, abort
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import select
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    recipients = db.Column(db.Text, nullable=False)
    cc = db.Column(db.Text, default="")
    bcc = db.Column(db.Text, default="")
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(16), nullable=False, default="draft")
    ses_message_id = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def addresses(raw):
    values = [v.strip() for v in raw.split(",") if v.strip()]
    if len(values) > 50:
        raise ValueError("Maximum 50 addresses per field")
    for value in values:
        name, address = parseaddr(value)
        if name or address != value or not re.fullmatch(r"[^\s@,]+@[^\s@,]+\.[^\s@,]+", value):
            raise ValueError("Use comma-separated email addresses")
    return values

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "")
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("Set SECRET_KEY before starting the application")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///cloudmail.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    csrf.init_app(app)

    @app.get("/")
    def home():
        return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(password) < 12:
                flash("Enter a valid email and a password of at least 12 characters.", "error")
            elif db.session.scalar(select(User).where(User.email == email)):
                flash("Account already exists.", "error")
            else:
                user = User(email=email, password_hash=generate_password_hash(password))
                db.session.add(user)
                db.session.commit()
                login_user(user)
                return redirect(url_for("dashboard"))
        return render_template("auth.html", mode="register")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            user = db.session.scalar(select(User).where(User.email == email))
            if user and check_password_hash(user.password_hash, request.form.get("password", "")):
                login_user(user)
                return redirect(url_for("dashboard"))
            flash("Invalid credentials.", "error")
        return render_template("auth.html", mode="login")

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        folder = request.args.get("folder", "sent")
        if folder not in ("sent", "draft"):
            abort(404)
        messages = db.session.scalars(
            select(Message).where(Message.user_id == current_user.id, Message.status == folder)
            .order_by(Message.created_at.desc())
        ).all()
        return render_template("dashboard.html", messages=messages, folder=folder)

    @app.route("/compose", methods=["GET", "POST"])
    @login_required
    def compose():
        if request.method == "POST":
            subject = request.form.get("subject", "").strip()[:255]
            body = request.form.get("body", "")
            to_raw = request.form.get("to", "")
            cc_raw = request.form.get("cc", "")
            bcc_raw = request.form.get("bcc", "")
            action = request.form.get("action", "draft")
            if not subject or not body or len(body) > 100000:
                flash("Subject and message are required (max 100,000 characters).", "error")
                return render_template("compose.html", values=request.form)
            try:
                to, cc, bcc = addresses(to_raw), addresses(cc_raw), addresses(bcc_raw)
                if action == "send" and not to:
                    raise ValueError("At least one To recipient is required")
                if len(to) + len(cc) + len(bcc) > 50:
                    raise ValueError("Maximum 50 total recipients")
            except ValueError as exc:
                flash(str(exc), "error")
                return render_template("compose.html", values=request.form)
            msg = Message(user_id=current_user.id, recipients=", ".join(to),
                          cc=", ".join(cc), bcc=", ".join(bcc), subject=subject, body=body)
            if action == "send":
                sender = os.getenv("SES_FROM_EMAIL")
                if not sender:
                    flash("SES_FROM_EMAIL is not configured.", "error")
                    return render_template("compose.html", values=request.form)
                try:
                    response = boto3.client("sesv2", region_name=os.getenv("AWS_REGION", "ap-south-1")).send_email(
                        FromEmailAddress=sender,
                        Destination={"ToAddresses": to, "CcAddresses": cc, "BccAddresses": bcc},
                        Content={"Simple": {"Subject": {"Data": subject, "Charset": "UTF-8"},
                                            "Body": {"Text": {"Data": body, "Charset": "UTF-8"}}}})
                    msg.status = "sent"
                    msg.ses_message_id = response["MessageId"]
                except (ClientError, BotoCoreError) as exc:
                    app.logger.exception("SES send failed")
                    flash("Email could not be submitted to SES. Check server logs.", "error")
                    return render_template("compose.html", values=request.form)
            db.session.add(msg)
            db.session.commit()
            flash("Submitted to SES." if msg.status == "sent" else "Draft saved.", "success")
            return redirect(url_for("dashboard", folder=msg.status))
        return render_template("compose.html", values={})

    @app.get("/health")
    def health():
        return {"status": "ok"}

    with app.app_context():
        db.create_all()
    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=False)
