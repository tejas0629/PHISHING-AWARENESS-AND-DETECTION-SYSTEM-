from flask import Flask, render_template, request, redirect, session
from flask_mail import Mail, Message
import random
import json
import os
import requests
import socket
from urllib.parse import urlparse
import time



app = Flask(__name__)
app.secret_key = "secret123"
# ---------- FREE HYBRID URL ANALYZER (no external API) ----------
from flask import Flask, render_template, request, redirect, session
from flask_mail import Mail, Message
import random
import json
import os
import requests
import socket
from urllib.parse import urlparse
import time



app = Flask(__name__)
app.secret_key = "secret123"
# ---------- FREE HYBRID URL ANALYZER (no external API) ----------
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
        return "suspicious", ["Malformed URL"]

    domain = parsed.hostname or ""
    domain = domain.lower()

    # 1) DNS resolution
    try:
        socket.gethostbyname(domain)
    except Exception:
        return "suspicious", ["Domain does not exist (DNS lookup failed)"]

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
    # domain like '192.168.0.1' -> suspicious
    parts = domain.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        reasons.append("Uses raw IP address")

    # 6) HTTP request: response, redirects, ssl
    try:
        start = time.time()
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "PDTA-Scanner/1.0"})
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

        if base != final:
            trusted_big_sites = {
                "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "amazon.com",
    "microsoft.com",
    "openai.com",
    "chatgpt.com"
            }
            # If final contains any trusted site substring, allow it
            if not any(t in final for t in trusted_big_sites):
                reasons.append("Redirects to a different domain")

    except requests.exceptions.Timeout:
        return "suspicious", ["Connection timed out"]
    except requests.exceptions.SSLError:
        return "suspicious", ["SSL/TLS certificate error"]
    except requests.exceptions.RequestException as e:
        # network-level error
        return "suspicious", [f"Network/request error: {e}"]

    # Final decision: if any reasons -> suspicious, else safe
    if reasons:
        return "suspicious", reasons
    return "safe", ["No issues detected"]

def save_url_result(url, status):
    file_path = "url.json"

    # Load existing data (must be a list)
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = []  # Fix wrong format
            except:
                data = []
    else:
        data = []

    # Add new record
    data.append({"url": url, "status": status})

    # Save back
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            try:
                return json.load(f)
            except:
                return {}
    return {}

def save_users():
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

users = load_users()


def generate_otp():
    return "".join(random.choices("0123456789", k=6))

def generate_captcha(length=6):
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ''.join(random.choices(chars, k=length))

@app.route("/")
def login():
    captcha = generate_captcha()       # generate CAPTCHA
    session["captcha"] = captcha       # store in session
    return render_template("login.html", captcha=captcha)


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name = request.form["name"]
        username = request.form["username"]
        email = request.form["email"]  # Add email input in register form
        password = request.form["password"]
        
        otp = "".join(random.choices("0123456789", k=6))
        session["temp_user"] = {"name": name, "username": username, "password": password, "email": email, "otp": otp}

        # Send OTP to email
        msg = Message(subject="Your OTP for Phishing Awareness ",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Hello {name},\n\nYour OTP for registration is for Phishing awareness and detection system: {otp}\n\nDo not share it with anyone."
        mail.send(msg)

        return render_template("verify.html")  # Remove demo OTP display
    return render_template("register.html")


@app.route("/verify", methods=["POST"])
def verify():
    u=session.get("temp_user")
    if not u: 
        return redirect("/register")

    if request.form["otp"] == u["otp"]:
        users[u["username"]] = {
            "name": u["name"],
            "username": u["username"],
            "email": u["email"],
            "password": u["password"]
        }

        save_users()   # <-- Save to JSON file
        session.pop("temp_user")
        return redirect("/")
    return "Invalid OTP"
@app.route("/auth", methods=["POST"])
def auth():
    user = request.form["username"]
    pw = request.form["password"]
    captcha_input = request.form["captcha_input"]

    if captcha_input != session.get("captcha"):
        return "CAPTCHA incorrect! Go back and try again."

    if user in users and users[user]["password"]==pw:
        session["user"] = user
        return redirect("/home")
    return "Invalid login"


@app.route("/home")
def home():
    if "user" not in session: return redirect("/")
    return render_template("home.html", user=session["user"])

@app.route('/fakesite')
def fakesite():
    return render_template("fakesite.html")

@app.route('/types')
def types():
    return render_template("phishing.html")

@app.route("/urlscanner")
def urlscanner():
    try:
        with open("url.json", "r") as f:
            history = json.load(f)
    except:
        history = []

    return render_template("urlscanner.html", history=history)

@app.route("/scan_url", methods=["POST"])
def scan_url():
    url = request.form.get("url_input", "").strip()

    if not url:
        return render_template("urlscanner.html", error="⚠ Please enter a URL!")

    # Auto-add scheme if missing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    # Run analyzer
    status, reasons = analyze_url(url)

    # Save to url.json (status stored as "safe"/"suspicious")
    save_url_result(url, status)

    # Load history
    try:
        with open("url.json", "r") as f:
            history = json.load(f)
    except:
        history = []

    # Counts (optional, used by templates that show safe/suspicious counts)
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

    # Save to url.json
    save_url_result(url, status)

    # Load history
    try:
        with open("url.json", "r") as f:
            history = json.load(f)
    except:
        history = []

    return render_template(
        "urlscanner.html",
        scanned_url=url,
        result=status,
        reasons=reasons,
        history=history
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route('/aboutus')
def aboutus():
    return render_template("aboutus.html")

# Configure mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='tejasupreti2964@gmail.com',  
    MAIL_PASSWORD='tlnf tmjy hffz tilr '      
)

mail = Mail(app)


if __name__=="__main__":
    app.run(debug=True)

def save_url_result(url, status):
    file_path = "url.json"

    # Load existing data (must be a list)
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = []  # Fix wrong format
            except:
                data = []
    else:
        data = []

    # Add new record
    data.append({"url": url, "status": status})

    # Save back
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            try:
                return json.load(f)
            except:
                return {}
    return {}

def save_users():
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

users = load_users()


def generate_otp():
    return "".join(random.choices("0123456789", k=6))

def generate_captcha(length=6):
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ''.join(random.choices(chars, k=length))

@app.route("/")
def login():
    captcha = generate_captcha()       # generate CAPTCHA
    session["captcha"] = captcha       # store in session
    return render_template("login.html", captcha=captcha)


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name = request.form["name"]
        username = request.form["username"]
        email = request.form["email"]  # Add email input in register form
        password = request.form["password"]
        
        otp = "".join(random.choices("0123456789", k=6))
        session["temp_user"] = {"name": name, "username": username, "password": password, "email": email, "otp": otp}

        # Send OTP to email
        msg = Message(subject="Your OTP for Phishing Awareness ",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Hello {name},\n\nYour OTP for registration is for Phishing awareness and detection system: {otp}\n\nDo not share it with anyone."
        mail.send(msg)

        return render_template("verify.html")  # Remove demo OTP display
    return render_template("register.html")


@app.route("/verify", methods=["POST"])
def verify():
    u=session.get("temp_user")
    if not u: 
        return redirect("/register")

    if request.form["otp"] == u["otp"]:
        users[u["username"]] = {
            "name": u["name"],
            "username": u["username"],
            "email": u["email"],
            "password": u["password"]
        }

        save_users()   # <-- Save to JSON file
        session.pop("temp_user")
        return redirect("/")
    return "Invalid OTP"
@app.route("/auth", methods=["POST"])
def auth():
    user = request.form["username"]
    pw = request.form["password"]
    captcha_input = request.form["captcha_input"]

    if captcha_input != session.get("captcha"):
        return "CAPTCHA incorrect! Go back and try again."

    if user in users and users[user]["password"]==pw:
        session["user"] = user
        return redirect("/home")
    return "Invalid login"


@app.route("/home")
def home():
    if "user" not in session: return redirect("/")
    return render_template("home.html", user=session["user"])

@app.route('/fakesite')
def fakesite():
    return render_template("fakesite.html")

@app.route('/types')
def types():
    return render_template("phishing.html")

@app.route("/urlscanner", methods=["GET", "POST"])
def urlscanner():
    if request.method == "POST":
        return scan_url()

    try:
        with open("url.json", "r") as f:
            history = json.load(f)
    except:
        history = []

    return render_template("urlscanner.html", history=history)

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

    return render_template(
        "urlscanner.html",
        scanned_url=url,
        result=status,
        reasons=reasons,
        history=history
    )

    # Save to url.json
    save_url_result(url, status)

    # Load history
    try:
        with open("url.json", "r") as f:
            history = json.load(f)
    except:
        history = []

    return render_template(
        "urlscanner.html",
        scanned_url=url,
        result=status,
        reasons=reasons,
        history=history
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route('/aboutus')
def aboutus():
    return render_template("aboutus.html")

# Configure mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='tejasupreti2964@gmail.com',  
    MAIL_PASSWORD='tlnf tmjy hffz tilr '      
)

mail = Mail(app)

if __name__ == "__main__":
    app.run(debug=True)
