from flask import Flask, render_template, request, redirect, session, jsonify
from flask_mail import Mail, Message
from urllib.parse import urlparse
from datetime import datetime
from dotenv import load_dotenv
import random
import json
import os
import requests
import socket
import time
from flask import session, send_file


# Load .env variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "secret123")  # fallback if not set

# Configure mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD")
)
mail = Mail(app)

# -------------------- Utilities --------------------

def analyze_url(url, timeout=6):
    """
    Returns: (status, reasons)
      - status: "safe" or "suspicious"
      - reasons: list of strings
    """
    reasons = []
    parsed = urlparse(url)

    # Basic URL check
    if not parsed.scheme or not parsed.netloc:
        reasons.append("Malformed URL")
        return "suspicious", reasons  # Malformed URL is fatal, can stop

    domain = parsed.hostname or ""
    domain = domain.lower()

    # 1) DNS resolution
    try:
        socket.gethostbyname(domain)
    except Exception:
        reasons.append("Domain does not exist (DNS lookup failed)")

    # 2) Suspicious TLDs
    bad_tlds = {"xyz", "top", "zip", "click", "work", "club", "info", "bid", "icu"}
    if any(domain.endswith("." + t) for t in bad_tlds):
        reasons.append("Suspicious top-level domain")

    # 3) Suspicious keywords
    keywords = ["login", "secure", "verify", "update", "confirm", "account", "bonus", "claim", "reward"]
    if any(k in url.lower() for k in keywords):
        reasons.append("Contains suspicious keywords")

    # 4) Too many subdomains
    if domain.count(".") >= 3:
        reasons.append("Too many subdomains")

    # 5) IP address URL
    parts = domain.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        reasons.append("Uses raw IP address")

    # 6) HTTP request: response, redirects, ssl
    try:
        start = time.time()
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "PDTA-Scanner/1.0"})
        elapsed = time.time() - start

        if elapsed > timeout:
            reasons.append("Slow website response")

        if len(r.history) > 5:
            reasons.append("Too many redirects")

        if r.status_code >= 400:
            reasons.append(f"HTTP error {r.status_code}")

        # --- REDIRECT CHECK (SAFE handling for www and trusted sites) ---
        final_domain = urlparse(r.url).hostname or ""
        base = domain.replace("www.", "")
        final = final_domain.replace("www.", "")

        trusted_big_sites = {
            "google.com", "youtube.com", "facebook.com", "instagram.com",
            "twitter.com", "x.com", "amazon.com", "microsoft.com",
            "openai.com", "chatgpt.com", "linkedin.com"
        }

        if base != final and not any(t in final for t in trusted_big_sites):
            reasons.append("Redirects to a different domain")

    except requests.exceptions.Timeout:
        reasons.append("Connection timed out")
    except requests.exceptions.SSLError:
        reasons.append("SSL/TLS certificate error")
    except requests.exceptions.RequestException as e:
        reasons.append(f"Network/request error: {e}")

    # Final decision: if any reasons -> suspicious, else safe
    return ("suspicious", reasons) if reasons else ("safe", ["No issues detected"])

def save_url_result(url, status):
    file_path = "url.json"
    data = []

    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    data = []
        except:
            data = []

    data.append({"url": url, "status": status})
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)


def load_users():
    if os.path.exists("users.json"):
        try:
            with open("users.json", "r") as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_users():
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)


def generate_otp():
    return "".join(random.choices("0123456789", k=6))


def generate_captcha(length=6):
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ''.join(random.choices(chars, k=length))


users = load_users()

# -------------------- Routes --------------------

@app.route("/")
def login():
    captcha = generate_captcha()
    session["captcha"] = captcha
    return render_template("login.html", captcha=captcha)


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        otp = generate_otp()
        session["temp_user"] = {"name": name, "username": username, "password": password, "email": email, "otp": otp}

        msg = Message(
            subject="Your OTP for Phishing Awareness",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"Hello {name},\n\nYour OTP for registration is: {otp}\n\nDo not share it with anyone."
        mail.send(msg)

        return render_template("verify.html")
    return render_template("register.html")


@app.route("/verify", methods=["POST"])
def verify():
    u = session.get("temp_user")
    if not u: 
        return redirect("/register")

    if request.form["otp"] == u["otp"]:
        users[u["username"]] = {
            "name": u["name"],
            "username": u["username"],
            "email": u["email"],
            "password": u["password"]
        }
        save_users()
        session.pop("temp_user")
        return redirect("/")
    return "Invalid OTP"


@app.route("/auth", methods=["POST"])
def auth():
    user = request.form["username"]
    pw = request.form["password"]
    captcha_input = request.form["captcha_input"]

    if captcha_input != session.get("captcha"):
        return "CAPTCHA incorrect!"

    if user in users and users[user]["password"] == pw:
        otp = generate_otp()
        session["otp_user"] = user
        session["login_otp"] = otp

        email = users[user]["email"]
        msg = Message(
            subject="Login Verification OTP",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"""
Hello {users[user]['name']},

We detected a login attempt.

Your OTP is: {otp}

If this was you, enter the OTP to continue.
If not, please ignore this email.
"""
        mail.send(msg)
        return redirect("/verify-login")

    return "Invalid login"


@app.route("/verify-login", methods=["GET", "POST"])
def verify_login():
    if request.method == "POST":
        user_otp = request.form["otp"]
        if user_otp == session.get("login_otp"):
            session["user"] = session.get("otp_user")
            session.pop("login_otp", None)
            session.pop("otp_user", None)
            return redirect("/home")
        return "Invalid OTP"
    return render_template("verify_login.html")


@app.route("/home")
def home():
    if "user" not in session: return redirect("/")
    return render_template("home.html", user=session["user"])


@app.route("/fakesite")
def fakesite():
    return render_template("fakesite.html")


@app.route("/types")
def types():
    return render_template("phishing.html")


@app.route("/urlscanner")
def urlscanner():
    try:
        with open("url.json", "r") as f:
            history = json.load(f)
    except:
        history = []

    safe_count = sum(1 for h in history if h.get("status") == "safe")
    suspicious_count = sum(1 for h in history if h.get("status") == "suspicious")

    return render_template(
        "urlscanner.html",
        history=history,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        total=len(history)
    )
@app.route("/export_pdf", methods=["POST"])
def export_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from flask import send_file

    try:
        with open("url.json", "r") as f:
            history = json.load(f)
    except:
        history = []

    if not history:
        return "No scan history available", 400

    file_path = "scan_report.pdf"
    c = canvas.Canvas(file_path, pagesize=A4)
    width, height = A4

    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "URL Detection Summary")
    y -= 30

    c.setFont("Helvetica", 11)

    for i, item in enumerate(history, start=1):
        line = f"{i}. {item.get('url','')}  -  {item.get('status','').upper()}"
        c.drawString(50, y, line)
        y -= 18
        if y < 50:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 11)

    c.save()
    return send_file(file_path, as_attachment=True)


@app.route("/scan_url", methods=["POST"])
def scan_url():
    url = request.form.get("url_input", "").strip()
    if not url:
        return render_template("urlscanner.html", error="⚠ Please enter a URL!")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    status, reasons = analyze_url(url)
    save_url_result(url, status)

    try:
        with open("url.json", "r") as f:
            history = json.load(f)
    except:
        history = []

    safe_count = sum(1 for e in history if e.get("status", "").lower() == "safe")
    suspicious_count = sum(1 for e in history if e.get("status", "").lower() == "suspicious")

    return render_template(
        "urlscanner.html",
        scanned_url=url,
        result=status,
        reasons=reasons,
        history=history,
        safe_count=safe_count,
        suspicious_count=suspicious_count
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/submit_kyc", methods=["POST"])
def submit_kyc():
    name = request.form.get("account_name")
    account = request.form.get("account_number")
    phone = request.form.get("phone")
    email = request.form.get("email")
    current_time = datetime.now().strftime("%d-%m-%Y %I:%M %p")

    kyc_data = {"name": name, "account": account, "phone": phone, "email": email, "time": current_time}

    file = "kycdetail.json"
    data = []

    if os.path.exists(file):
        try:
            with open(file, "r") as f:
                data = json.load(f)
        except:
            data = []

    data.append(kyc_data)
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

    msg = Message(
        subject="SBI Alert: KYC Verification Successful",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    msg.body = f"""
Dear {name},

Your KYC verification is successful.
Account Number: {account}
Time: {current_time}

Your Debit/Credit card is now active.

Thank you,
Team SBI
"""
    mail.send(msg)
    return jsonify({"success": True})


@app.route("/aboutus")
def aboutus():
    return render_template("aboutus.html")


# -------------------- Run App --------------------
if __name__ == "__main__":
    app.run(debug=True)
