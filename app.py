from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import asyncio
import aiohttp
import stripe
import os
from datetime import datetime, timedelta

from analysis.scraper import SCRAPERS
from analysis.analyzer import analyze_wallet

# ──────────────────────────────
# APP CONFIG
# ──────────────────────────────
app = Flask(__name__)
app.secret_key = 'supersecret'

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users_tokens_with_admin.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# E-Mail SMTP Beispiel
app.config["MAIL_SERVER"] = "smtp.mailtrap.io"
app.config["MAIL_PORT"] = 2525
app.config["MAIL_USERNAME"] = "your_mail_username"
app.config["MAIL_PASSWORD"] = "your_mail_password"
app.config["MAIL_USE_TLS"] = True

db = SQLAlchemy(app)
mail = Mail(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Stripe Keys (Testmodus)
stripe.api_key = "sk_test_YOUR_SECRET_KEY"
STRIPE_PRICE_MAP = {
    "price_12h": 12,
    "price_1d": 24,
    "price_1w": 24 * 7,
    "price_1m": 24 * 30,
    "price_lifetime": None
}

# ──────────────────────────────
# MODELLE
# ──────────────────────────────
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default="user")
    tokens = db.relationship('AccessToken', backref='user', lazy=True)

class AccessToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role != role:
                return "Nicht autorisiert", 403
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Zugriffsschutz vor JEDER Anfrage außer Login/Register
@app.before_request
def check_token():
    if current_user.is_authenticated and request.endpoint not in ["login", "logout", "buy", "create_checkout_session", "webhook"]:
        token = AccessToken.query.filter_by(user_id=current_user.id).order_by(AccessToken.created_at.desc()).first()
        if not token or (token.expires_at and token.expires_at < datetime.utcnow()):
            return redirect(url_for("buy"))

# ──────────────────────────────
# ROUTEN
# ──────────────────────────────
@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Falsche Zugangsdaten.")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/buy")
@login_required
def buy():
    return render_template("buy.html")

@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    price_id = request.form.get("price_id")
    if price_id not in STRIPE_PRICE_MAP:
        return "Ungültiger Preis", 400
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="payment",
        success_url=url_for("success", _external=True),
        cancel_url=url_for("cancel", _external=True),
        metadata={"user_id": current_user.id, "price_id": price_id}
    )
    return redirect(session.url)

@app.route("/success")
@login_required
def success():
    # Benutzer bekommt E-Mail nach erfolgreichem Kauf
    try:
        msg = Message("Zugriff aktiviert", recipients=[current_user.email])
        msg.body = "Dein Wallet Analyzer Zugang wurde freigeschaltet."
        mail.send(msg)
    except Exception:
        pass
    return render_template("success.html")

@app.route("/cancel")
@login_required
def cancel():
    return render_template("cancel.html")

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.data
    event = None
    try:
        event = stripe.Event.construct_from(
            request.get_json(), stripe.api_key
        )
    except Exception as e:
        return str(e), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_id = session["metadata"]["user_id"]
        price_id = session["metadata"]["price_id"]
        hours = STRIPE_PRICE_MAP.get(price_id)
        now = datetime.utcnow()
        expires = None if hours is None else now + timedelta(hours=hours)
        token = AccessToken(user_id=user_id, token_type=price_id, created_at=now, expires_at=expires)
        db.session.add(token)
        db.session.commit()
    return "ok", 200

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    users = User.query.all()
    return render_template("admin/dashboard.html", users=users)

@app.route("/admin/toggle-role/<int:user_id>", methods=["POST"])
@role_required("admin")
def toggle_role(user_id):
    user = User.query.get_or_404(user_id)
    if user.email == "admin@example.com":
        return "Admin kann nicht geändert werden", 403
    user.role = "admin" if user.role == "user" else "user"
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@role_required("admin")
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.email == "admin@example.com":
        return "Admin kann nicht gelöscht werden", 403
    AccessToken.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    data = request.get_json()
    chain = data.get("chain")
    if chain not in SCRAPERS:
        return jsonify({"error": "Unsupported chain"}), 400

    wallets = SCRAPERS[chain]()
    ADDRESS_LIMIT = 10

    async def run_analysis():
        results = []
        async with aiohttp.ClientSession() as session:
            for addr in wallets[:ADDRESS_LIMIT]:
                res = await analyze_wallet(session, addr, chain)
                results.append(res)
        return results

    results = asyncio.run(run_analysis())
    return jsonify(results)

# ──────────────────────────────
# START
# ──────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
