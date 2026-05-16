from functools import wraps
from flask import Flask, redirect, render_template, request, session, url_for
import pickle
import re
import numpy as np
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash
from dataset import TRUSTED
from feature_extractor import extract_features
from notifier import send_agent_alert
from scan_store import (
    approve_manual_monitor_entry,
    create_agent,
    create_user,
    get_agent_by_id,
    get_agent_by_username,
    get_approved_decision,
    get_manual_monitor_entries,
    get_user_by_id,
    get_user_by_username,
    get_user_scans,
    init_db,
    save_user_scan,
    save_manual_monitor_entry,
    update_user_profile,
)


# Load trained model generated from phishing_urls.csv
model = pickle.load(open("model/phishing_model.pkl", "rb"))

app = Flask(__name__)
app.secret_key = "shieldscan-local-dev-secret"
init_db()

DEFAULT_AGENT_USERNAME = "agent"
DEFAULT_AGENT_PASSWORD = "agent123"

PREDICTION_LABELS = {
    0: "Phishing Website",
    1: "Safe Website",
}

MONITOR_MIN_RISK = 40
MONITOR_MAX_RISK = 60
PHONE_PATTERN = re.compile(r"^\+?[1-9]\d{9,14}$")


def normalize_domain(value):
    parsed = urlparse(value if "://" in value else f"https://{value}")
    domain = parsed.netloc.lower().split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def normalize_review_url(value):
    parsed = urlparse(value.strip() if "://" in value else f"https://{value.strip()}")
    scheme = parsed.scheme.lower() or "https"
    domain = parsed.netloc.lower().split(":")[0]
    path = parsed.path.rstrip("/")

    if not path:
        path = "/"

    normalized = f"{scheme}://{domain}{path}"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"

    return normalized


def normalize_phone_number(value):
    phone = re.sub(r"[\s()-]", "", value.strip())
    raw_digits = re.sub(r"\D", "", phone)

    if not phone:
        return ""

    if raw_digits and len(set(raw_digits[-10:])) == 1:
        return ""

    if phone.isdigit() and len(phone) == 10:
        phone = f"+91{phone}"

    if not PHONE_PATTERN.fullmatch(phone):
        return ""

    return phone


TRUSTED_DOMAINS = {normalize_domain(site) for site in TRUSTED}


def ensure_default_agent():
    if not get_agent_by_username(DEFAULT_AGENT_USERNAME):
        create_agent(
            DEFAULT_AGENT_USERNAME,
            generate_password_hash(DEFAULT_AGENT_PASSWORD),
            "Security Agent",
        )


ensure_default_agent()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    return get_user_by_id(user_id)


def current_agent():
    agent_id = session.get("agent_id")
    if not agent_id:
        return None

    return get_agent_by_id(agent_id)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def agent_login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not current_agent():
            return redirect(url_for("agent_login"))

        return view(*args, **kwargs)

    return wrapped_view


def is_trusted_url(url):
    domain = normalize_domain(url)
    return any(domain == trusted or domain.endswith(f".{trusted}") for trusted in TRUSTED_DOMAINS)


@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    prediction = ""
    user = current_user()

    if request.method == "POST":
        url = request.form["url"]
        normalized_url = normalize_review_url(url)
        features = np.array(extract_features(url)).reshape(1, -1)

        result = int(model.predict(features)[0])
        probability = model.predict_proba(features)[0]

        phishing_index = list(model.classes_).index(0)
        phishing_risk = round(float(probability[phishing_index]) * 100, 2)

        label = PREDICTION_LABELS.get(result, "Unknown Website")
        trusted = is_trusted_url(url)
        if trusted:
            label = "Safe Website"
            phishing_risk = 0

        approved_decision = get_approved_decision(url, normalized_url)
        needs_manual_review = MONITOR_MIN_RISK <= phishing_risk <= MONITOR_MAX_RISK
        scan_status = "complete"

        if approved_decision:
            label = approved_decision["manual_result"]
            phishing_risk = round(float(approved_decision["risk"]), 2)
            scan_status = "agent_approved"
            prediction = f"{label} (Agent Approved, Risk: {phishing_risk}%)"
        elif needs_manual_review:
            scan_status = "pending_manual_review"
            created_alert = save_manual_monitor_entry(
                user["id"],
                url,
                normalized_url,
                label,
                phishing_risk,
                trusted,
            )
            if created_alert:
                send_agent_alert(url, phishing_risk, user)
            prediction = (
                f"Alert Zone: This URL has a risk factor between 40% and 60% "
                f"(Risk: {phishing_risk}%). Manual verification is required. "
                "Our agents are working on it. Please wait for a minute to get the final output."
            )
        else:
            prediction = f"{label} (Risk: {phishing_risk}%)"

        save_user_scan(user["id"], url, normalized_url, label, phishing_risk, scan_status)

    return render_template("index.html", prediction=prediction, user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    form_values = {}

    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        display_name = request.form["display_name"].strip() or username
        phone = normalize_phone_number(request.form.get("phone", ""))
        about = request.form.get("about", "").strip()
        form_values = {
            "username": username,
            "display_name": display_name,
            "phone": request.form.get("phone", "").strip(),
            "about": about,
        }

        if not username or not password:
            error = "Username and password are required."
        elif not phone:
            error = "Enter a valid mobile number, for example +919876543210."
        elif get_user_by_username(username):
            error = "That username is already registered."
        else:
            create_user(username, generate_password_hash(password), display_name, phone, about)
            user = get_user_by_username(username)
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("home"))

    return render_template("auth.html", mode="register", error=error, form=form_values)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    form_values = {}

    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        user = get_user_by_username(username)
        form_values = {"username": username}

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("home"))

        error = "Invalid username or password."

    return render_template("auth.html", mode="login", error=error, form=form_values)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    error = ""

    if request.method == "POST":
        phone = normalize_phone_number(request.form.get("phone", ""))
        if not phone:
            scans = get_user_scans(user["id"])
            return render_template("profile.html", user=user, scans=scans, error="Enter a valid mobile number, for example +919876543210.")

        update_user_profile(
            user["id"],
            request.form["display_name"].strip() or user["username"],
            phone,
            request.form.get("about", "").strip(),
        )
        return redirect(url_for("profile"))

    scans = get_user_scans(user["id"])
    user = current_user()
    return render_template("profile.html", user=user, scans=scans, error=error)


@app.route("/agent/login", methods=["GET", "POST"])
def agent_login():
    error = ""

    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        agent = get_agent_by_username(username)

        if agent and check_password_hash(agent["password_hash"], password):
            session.clear()
            session["agent_id"] = agent["id"]
            return redirect(url_for("agent_monitor"))

        error = "Invalid agent username or password."

    return render_template("agent_login.html", error=error)


@app.route("/agent/logout")
def agent_logout():
    session.clear()
    return redirect(url_for("agent_login"))


@app.route("/monitor")
def monitor_redirect():
    return redirect(url_for("agent_monitor"))


@app.route("/agent/monitor")
@agent_login_required
def agent_monitor():
    scans = get_manual_monitor_entries()
    return render_template("monitor.html", scans=scans, agent=current_agent())


@app.route("/agent/monitor/<int:entry_id>/approve", methods=["POST"])
@agent_login_required
def approve_monitor_entry(entry_id):
    manual_result = request.form["manual_result"]
    approve_manual_monitor_entry(entry_id, manual_result, current_agent()["id"])
    return redirect(url_for("agent_monitor"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
