from flask import Flask, send_from_directory, request, redirect, session, jsonify, render_template
from flask_cors import CORS
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import sqlite3, os, re, json, traceback
from groq import Groq
import smtplib, random, socket, time
from threading import Thread
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from urllib.parse import urlparse

# ---------- Load .env ----------
load_dotenv()  # reads back-end/.env automatically

# ---------- Env / config ----------
db_url = os.getenv("DATABASE_URL", "")
print("[DB] DATABASE_URL =", db_url)
print("[DB] Host parsed  =", urlparse(db_url).hostname)

REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:5000/auth/google/callback")

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "")
OTP_EXP_MINUTES = int(os.getenv("OTP_EXP_MINUTES", "10"))

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@navona.ai")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Navona@123")

# ---------- Paths ----------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.dirname(os.path.abspath(__file__))
FRONT_DIR = os.path.join(BASE_DIR, "front-end")
PAGES_DIR = os.path.join(BASE_DIR, "front-end", "pages")
STYLES_DIR = os.path.join(BASE_DIR, "front-end", "styles")

print("FRONT_DIR exists?", os.path.exists(FRONT_DIR))
print("index.html exists?", os.path.exists(os.path.join(FRONT_DIR, "index.html")))

# ---------- Flask app ----------
app = Flask(__name__, static_folder=PAGES_DIR, static_url_path="", template_folder=PAGES_DIR)

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "navona_dev_secret_key")
CORS(app)

# ---------- Groq sanity print ----------
print("key present?", bool(os.getenv("GROQ_API_KEY")))
try:
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    ms = client.models.list()
    print("models count:", len(ms.data))
    print("first model:", ms.data[0].id if ms.data else None)
except Exception as e:
    print("EXC TYPE:", type(e).__name__)
    print("EXC STR :", str(e))
    traceback.print_exc()

# ---------- Health ----------
@app.route("/health")
def health():
    return {"status": "ok"}, 200

# ---------- Static entry ----------
@app.route("/")
def home():
    return send_from_directory(FRONT_DIR, "index.html")

@app.route("/index.html")
def index_file():
    return send_from_directory(FRONT_DIR, "index.html")

# Favicon/Icon helpers (avoid 404s in logs if files exist)
@app.route("/favicon.ico")
def favicon():
    path = os.path.join(FRONT_DIR, "favicon.ico")
    if os.path.exists(path):
        return send_from_directory(FRONT_DIR, "favicon.ico")
    return ("", 204)

@app.route("/icon.jpg")
def icon_jpg():
    path = os.path.join(FRONT_DIR, "icon.jpg")
    if os.path.exists(path):
        return send_from_directory(FRONT_DIR, "icon.jpg")
    return ("", 204)

# ---------- Helper: are we using Postgres? ----------
def using_postgres() -> bool:
    url = (os.getenv("DATABASE_URL", "") or "").strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url.startswith("postgresql://")

# ---------- DB (Postgres if DATABASE_URL set; else SQLite) ----------
def get_db():
    import os as _os, sqlite3 as _sqlite3
    url = _os.getenv("DATABASE_URL", "").strip()

    # Normalize old scheme if present
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    # ---- Postgres path (psycopg 3) ----
    if url.startswith("postgresql://"):
        import psycopg
        from psycopg_pool import ConnectionPool

        class QMarkCursor:
            def __init__(self, cur):
                self._cur = cur
            def execute(self, query, vars=None):
                if vars is not None:
                    query = query.replace("?", "%s")
                return self._cur.execute(query, vars)
            def executemany(self, query, vars_list):
                query = query.replace("?", "%s")
                return self._cur.executemany(query, vars_list)
            def fetchone(self):
                return self._cur.fetchone()
            def fetchall(self):
                return self._cur.fetchall()
            @property
            def rowcount(self):
                return self._cur.rowcount
            def close(self):
                return self._cur.close()

        class PooledConn:
            def __init__(self, pool):
                self._pool = pool
                self._conn = pool.getconn()
            def cursor(self):
                return QMarkCursor(self._conn.cursor())
            def commit(self):
                return self._conn.commit()
            def rollback(self):
                return self._conn.rollback()
            def close(self):
                if getattr(self, "_conn", None) is not None:
                    self._pool.putconn(self._conn)
                    self._conn = None

        # small global pool
        global _PG_POOL
        try:
            _PG_POOL
        except NameError:
            _PG_POOL = None
        if _PG_POOL is None:
            _PG_POOL = ConnectionPool(url, min_size=1, max_size=5)
            print("[DB] psycopg3 pool created")

        conn = PooledConn(_PG_POOL)

        # Ensure schema (safe if exists)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
              name TEXT,
              email TEXT UNIQUE,
              password TEXT,
              google_id TEXT,
              provider TEXT,
              credits INTEGER DEFAULT 2,
              is_verified INTEGER DEFAULT 0,
              otp_hash TEXT,
              otp_expires_at TEXT
            );
        """)
        conn.commit()
        return conn

    # ---- SQLite fallback ----
    db_path = os.path.join(APP_DIR, "users.db")
    conn = _sqlite3.connect(db_path, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            google_id TEXT,
            provider TEXT,
            credits INTEGER DEFAULT 2,
            is_verified INTEGER DEFAULT 0,
            otp_hash TEXT,
            otp_expires_at TEXT
        )
    """)
    conn.commit()
    return conn

# ---------- DB check ----------
@app.route("/__dbcheck")
def __dbcheck():
    try:
        url = os.getenv("DATABASE_URL", "")
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        host = urlparse(url).hostname if url else None
        print("[DBCHECK] Using host:", host)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        res = cur.fetchone()
        cur.close()
        conn.close()

        return {"ok": True, "db_host": host, "result": res[0]}, 200
    except Exception as e:
        traceback.print_exc()
        return {"ok": False, "error": str(e)}, 500

# ---------- Admin auth guard ----------
def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        # Primary: explicit admin session
        if session.get("is_admin"):
            return f(*a, **k)

        # Fallback: allow the configured ADMIN_EMAIL user (if logged in) to access
        uid = session.get("user_id")
        if uid:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT email FROM users WHERE id = ?", (uid,))
            row = cur.fetchone()
            conn.close()

            ADMIN_EMAIL_CFG = os.getenv("ADMIN_EMAIL")
            if row and ADMIN_EMAIL_CFG and row[0] == ADMIN_EMAIL_CFG:
                return f(*a, **k)

        # Not admin → go to admin login
        return redirect("/admin-login")
    return w

# ---------- Admin login ----------
@app.route("/admin-login", methods=["GET", "POST", "HEAD"])
def admin_login():
    if request.method == "HEAD":
        return ("", 200)

    if request.method == "GET":
        return send_from_directory(PAGES_DIR, "admin_login.html")

    email = (request.form.get("email") or "").strip()
    password = (request.form.get("password") or "").strip()

    admin_email = os.getenv("ADMIN_EMAIL")
    admin_pass = os.getenv("ADMIN_PASSWORD")

    if not admin_email or not admin_pass:
        return render_template(
            "admin_login.html",
            error="Server admin credentials not configured. Ask the maintainer to set ADMIN_EMAIL and ADMIN_PASSWORD in the hosting environment."
        )

    if email == admin_email and password == admin_pass:
        session["is_admin"] = True
        session["admin_login_test"] = "ok"
        return redirect("/admin")

    return render_template("admin_login.html", error="Invalid email or password. Try again.")

# ---------- Admin routes ----------
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, email, credits, provider, 
               COALESCE(is_verified, 0) 
        FROM users 
        ORDER BY id DESC
    """)
    users_data = cur.fetchall()
    conn.close()

    users_list = [
        {
            "id": u[0],
            "name": u[1],
            "email": u[2],
            "credits": u[3],
            "provider": u[4],
            "is_verified": bool(u[5]),
        }
        for u in users_data
    ]
    return render_template("admin.html", users=users_list)

@app.route("/admin/user/<int:user_id>/credits", methods=["POST"])
@admin_required
def admin_user_credits(user_id):
    delta_raw = request.form.get("delta", "0")
    try:
        delta = int(delta_raw)
    except ValueError:
        delta = 0

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET credits = CASE
            WHEN COALESCE(credits,0) + ? < 0 THEN 0
            ELSE COALESCE(credits,0) + ?
        END
        WHERE id = ?
    """, (delta, delta, user_id))
    conn.commit()
    conn.close()
    return redirect("/admin")

@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    try:
        override_id = request.form.get("user_id") or (request.json or {}).get("user_id") if request.is_json else None
        target_id = int(override_id) if override_id else int(user_id)

        if session.get("user_id") == target_id:
            print(f"[admin] Prevented self-delete: user {target_id}")
            return redirect("/admin")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (target_id,))
        deleted = cur.rowcount or 0
        conn.commit()
        conn.close()

        print(f"[admin] Delete user id={target_id}, affected={deleted}")
        return redirect("/admin")
    except Exception:
        traceback.print_exc()
        return redirect("/admin")

# ---------- Email / OTP ----------
import ssl  # at top with other imports

def send_email(to_email: str, subject: str, html_body: str) -> bool:
    ...
    use_ssl = (os.getenv("SMTP_USE_SSL", "false").lower() == "true")
    debug_on = (os.getenv("SMTP_DEBUG", "false").lower() == "true")

    t0 = time.time()
    try:
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, int(SMTP_PORT), timeout=10, context=context) as s:
                if debug_on: s.set_debuglevel(1)
                t_conn = time.time()
                s.ehlo()
                s.login(SMTP_USER, SMTP_PASS)
                t_auth = time.time()
                s.sendmail(SMTP_FROM, [to_email], msg.as_string())
                t_send = time.time()
        else:
            context = ssl.create_default_context()
            with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT), timeout=10) as s:
                if debug_on: s.set_debuglevel(1)
                t_conn = time.time()
                s.ehlo()
                s.starttls(context=context)
                t_tls = time.time()
                s.ehlo()
                s.login(SMTP_USER, SMTP_PASS)
                t_auth = time.time()
                s.sendmail(SMTP_FROM, [to_email], msg.as_string())
                t_send = time.time()
                print(f"[email] timings: connect={(t_conn-t0):.3f}s  tls={(t_tls-t_conn):.3f}s  "
                      f"auth={(t_auth-t_tls):.3f}s  send={(t_send-t_auth):.3f}s  total={(t_send-t0):.3f}s")
        return True
    except (socket.timeout, smtplib.SMTPResponseException, smtplib.SMTPException, OSError) as e:
        print("[email] FAILED:", e)
        return False


def send_email_async(to_email: str, subject: str, html_body: str, otp: str = "") -> None:
    def _run():
        sent = send_email(to_email, subject, html_body)
        if not sent and os.getenv("DEV_SHOW_OTP", "false").lower() == "true" and otp:
            print(f"[DEV_ONLY_OTP] email={to_email} otp={otp}")
    Thread(target=_run, daemon=True).start()

def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"

def otp_expiry_iso() -> str:
    return (datetime.utcnow() + timedelta(minutes=OTP_EXP_MINUTES)).isoformat()

# ---------- Groq helper ----------
def call_groq_generate_roadmap(goal, skill_level, time_per_day, deadline, resource_preference):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set")

    primary = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    fallback = "llama-3.1-8b-instant"

    client = Groq(api_key=api_key)

    system_msg = (
        "You are Navona. Respond with STRICT JSON ONLY following this schema:\n"
        '{ "weeks": [ { "week": <int>, "topics": ["..."], "resources": ["..."] } ] }\n'
        "Choose 4–12 weeks based on the deadline. Topics must be actionable. "
        "Resources should be titles or search terms "
    )
    user_msg = (
        f"Goal: {goal}\nSkill Level: {skill_level}\nTime/Day: {time_per_day}\n"
        f"Deadline: {deadline}\nResource Preference: {resource_preference}\n\n"
        'Return JSON ONLY. If unsure, return {"weeks":[]}.'
    )

    def _call(model):
        return client.chat.completions.create(
            model=model,
            temperature=0.4,
            max_tokens=1800,
            top_p=0.9,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            timeout=30,
        )

    try:
        resp = _call(primary)
    except Exception:
        resp = _call(fallback)

    content = resp.choices[0].message.content.strip()
    if content.startswith("```"):
        content = content.strip("`").split("\n", 1)[-1]
    data = json.loads(content)
    if not isinstance(data, dict) or "weeks" not in data:
        raise ValueError("Groq response missing 'weeks'")
    return data

# ---------- Auth helpers ----------
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "user_id" not in session:
            return redirect("/login")
        return f(*a, **k)
    return w

def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, email, provider, credits FROM users WHERE id=?", (uid,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"name": row[0], "email": row[1], "provider": row[2], "credits": row[3]}

# ---------- Pages ----------
@app.route("/terms")
def terms():
    return send_from_directory(PAGES_DIR, "terms.html")

@app.route("/login", methods=["GET", "POST", "HEAD"])
def login():
    if request.method == "HEAD":
        return ("", 200)

    if request.method == "GET":
        return send_from_directory(PAGES_DIR, "login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, password, provider, is_verified FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "No account found with this email"}), 404
    if user[3] == "google":
        return jsonify({"error": "This account uses Google Sign-In. Click 'Continue with Google'."}), 401
    if not check_password_hash(user[2], password):
        return jsonify({"error": "Incorrect password"}), 401
    if int(user[4] or 0) == 0:
        session["pending_email"] = email
        return redirect(f"/verify?email={email}", code=303)
    session["user_id"] = user[0]
    session["user_name"] = user[1]
    return redirect("/dashboard")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return send_from_directory(PAGES_DIR, "signup.html")

    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()

    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400
    if not re.match(r"^[A-Za-z ]+$", name):
        return jsonify({"error": "Invalid name. Use letters and spaces only."}), 400
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
        return jsonify({"error": "Invalid email format."}), 400
    if not re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$", password):
        return jsonify({"error": "Weak password. Use 8+ chars with Aa1&"}), 400

    conn = get_db()
    cur = conn.cursor()

    # ensure email unique
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    if cur.fetchone():
        conn.close()
        return jsonify({"error": "Email already registered"}), 409

    # create user (unverified)
    hashed = generate_password_hash(password)
    if using_postgres():
        cur.execute(
            "INSERT INTO users (name,email,password,provider,credits,is_verified) VALUES (?,?,?,?,?,?) RETURNING id",
            (name, email, hashed, "local", 2, 0)
        )
        user_id = cur.fetchone()[0]
    else:
        cur.execute(
            "INSERT INTO users (name,email,password,provider,credits,is_verified) VALUES (?,?,?,?,?,?)",
            (name, email, hashed, "local", 2, 0)
        )
        user_id = cur.lastrowid

    conn.commit()

    # generate + store OTP (UPDATE existing row — do NOT insert again)
    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    cur.execute(
        "UPDATE users SET otp_hash = ?, otp_expires_at = ? WHERE id = ?",
        (otp_hash, otp_expiry_iso(), user_id)
    )
    conn.commit()

    # build email
    html = f"""
    <div style="font-family:Arial,sans-serif">
      <h2>Navona – Verify your email</h2>
      <p>Hello {name}, You're one step ahead to explore <b>Navona!</b></p>
      <p>Your One-Time Password:</p>
      <p style="font-size:24px;font-weight:bold;letter-spacing:2px">{otp}</p>
      <p>This code expires in {OTP_EXP_MINUTES} minutes.</p>
    </div>
    """

    # non-blocking email send (redirect is instant)
    send_email_async(email, "Navona – Verify your email", html, otp=otp)

    conn.close()

    # go to verify page (POST -> GET)
    session["pending_email"] = email
    return redirect(f"/verify?email={email}", code=303)

# ---------- Static: CSS ----------
@app.route("/styles/<path:filename>")
def styles(filename):
    return send_from_directory(STYLES_DIR, filename)

# ---------- Google OAuth ----------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

AUTH_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
SCOPE = ["openid", "email", "profile"]

def require_google_creds():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return ("Google OAuth is not configured. Set GOOGLE_CLIENT_ID and "
                "GOOGLE_CLIENT_SECRET in back-end/.env"), 500
    return None

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "GET":
        email = request.args.get("email") or session.get("pending_email") or ""
        return render_template("verify.html", email=email)

    email = (request.form.get("email") or "").strip().lower()
    code = (request.form.get("otp") or "").strip()
    if not email or not code:
        return render_template("verify.html", email=email, error="Email and OTP are required.")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, otp_hash, otp_expires_at, is_verified FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return render_template("verify.html", email=email, error="No account found for this email.")

    user_id, name, otp_hash, otp_exp_at, is_verified = row
    if int(is_verified or 0) == 1:
        conn.close()
        return redirect("/login")

    if not otp_hash or not otp_exp_at:
        conn.close()
        return render_template("verify.html", email=email, error="No active OTP. Please resend.")

    try:
        exp = datetime.fromisoformat(otp_exp_at)
    except Exception:
        conn.close()
        return render_template("verify.html", email=email, error="Invalid OTP state. Please resend.")

    if datetime.utcnow() > exp:
        conn.close()
        return render_template("verify.html", email=email, error="OTP expired. Please resend.")

    if not check_password_hash(otp_hash, code):
        conn.close()
        return render_template("verify.html", email=email, error="Incorrect OTP.")

    cur.execute("UPDATE users SET is_verified=1, otp_hash=NULL, otp_expires_at=NULL WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    session["user_id"] = user_id
    session["user_name"] = name
    session.pop("pending_email", None)
    return redirect("/dashboard")

@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = (request.form.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, is_verified FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "No account found"}), 404
    user_id, name, is_verified = row
    if int(is_verified or 0) == 1:
        conn.close()
        return jsonify({"message": "Already verified. Please login."}), 200

    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    cur.execute("UPDATE users SET otp_hash=?, otp_expires_at=? WHERE id=?",
                (otp_hash, otp_expiry_iso(), user_id))
    conn.commit()
    conn.close()

    html = f"""
    <div style="font-family:Arial,sans-serif">
      <h2>Navona – Your new OTP</h2>
      <p>Hello {name},</p>
      <p>Your new One-Time Password:</p>
      <p style="font-size:24px;font-weight:bold;letter-spacing:2px">{otp}</p>
      <p>This code expires in {OTP_EXP_MINUTES} minutes.</p>
    </div>
    """
    # non-blocking email send
    send_email_async(email, "Navona – Your new OTP", html, otp=otp)

    session["pending_email"] = email
    return jsonify({"message": "OTP resent to your email."}), 200

@app.route("/auth/google")
def auth_google():
    err = require_google_creds()
    if err:
        return err
    google = OAuth2Session(GOOGLE_CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
    authorization_url, state = google.authorization_url(
        AUTH_BASE_URL, access_type="offline", prompt="consent"
    )
    session["oauth_state"] = state
    return redirect(authorization_url)

@app.route("/auth/google/callback")
def auth_google_callback():
    err = require_google_creds()
    if err:
        return err
    if "oauth_state" not in session:
        return "State missing. Start again.", 400

    google = OAuth2Session(GOOGLE_CLIENT_ID, state=session["oauth_state"], redirect_uri=REDIRECT_URI)
    token = google.fetch_token(
        TOKEN_URL,
        client_secret=GOOGLE_CLIENT_SECRET,
        authorization_response=request.url
    )

    info = google.get(USERINFO_URL).json()
    email = info.get("email")
    name = info.get("name") or email
    gid = info.get("sub")
    if not email:
        return "Failed to get email from Google.", 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if not row:
        if using_postgres():
            cur.execute(
                "INSERT INTO users (name,email,google_id,provider,credits) VALUES (?,?,?,?,?) RETURNING id",
                (name, email, gid, "google", 2)
            )
            user_id = cur.fetchone()[0]
        else:
            cur.execute(
                "INSERT INTO users (name,email,google_id,provider,credits) VALUES (?,?,?,?,?)",
                (name, email, gid, "google", 2)
            )
            user_id = cur.lastrowid
        conn.commit()
    else:
        user_id = row[0]
    conn.close()

    session["user_id"] = user_id
    session["user_name"] = name
    return redirect("/dashboard")

# ---------- Generate ----------
@app.route("/generate", methods=["GET", "POST"])
@login_required
def generate_page():
    if request.method == "GET":
        return send_from_directory(PAGES_DIR, "generate.html")

    goal = (request.form.get("goal") or "").strip()
    custom = (request.form.get("customGoal") or "").strip()
    final_goal = custom if goal == "Other" and custom else goal
    skill = (request.form.get("skill_level") or "").strip()
    time_per_day = (request.form.get("time_per_day") or "").strip()
    deadline = (request.form.get("deadline") or "").strip()
    resource = (request.form.get("resource_preference") or "").strip()

    if not final_goal or not skill or not time_per_day or not deadline or not resource:
        print("[/generate] Missing fields:", final_goal, skill, time_per_day, deadline, resource)
        return redirect("/generate")

    uid = session["user_id"]
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET credits = COALESCE(credits,0) - 1 WHERE id=? AND COALESCE(credits,0) > 0",
        (uid,)
    )
    conn.commit()
    had_credit = (cur.rowcount == 1)
    print(f"[/generate] Decrement credits for user {uid}: had_credit={had_credit}")

    if not had_credit:
        conn.close()
        print("[/generate] No credits left — redirecting to /dashboard")
        return redirect("/dashboard")

    try:
        print("[/generate] Calling Groq...")
        roadmap = call_groq_generate_roadmap(final_goal, skill, time_per_day, deadline, resource)
        print("[/generate] Groq OK. Weeks:", len(roadmap.get("weeks", [])))
    except Exception as e:
        cur.execute("UPDATE users SET credits = COALESCE(credits,0) + 1 WHERE id=?", (uid,))
        conn.commit()
        conn.close()
        print("[/generate] Groq FAILED:", repr(e))
        return f"Roadmap generation failed: {e}", 500

    conn.close()
    return render_template(
        "output.html",
        user=get_current_user(),
        goal=final_goal,
        skill=skill,
        time_per_day=time_per_day,
        deadline=deadline,
        resource_preference=resource,
        roadmap=roadmap
    )

# ---------- Dashboard ----------
@app.route("/__smtp_diag")
def __smtp_diag():
    mode = (request.args.get("mode") or "").lower()  # "tls" or "ssl"
    to = request.args.get("to")
    if not to:
        return {"ok": False, "error": "missing ?to=recipient@example.com"}, 400

    if mode == "ssl":
        os.environ["SMTP_USE_SSL"] = "true";  os.environ["SMTP_PORT"] = os.getenv("SMTP_PORT") or "465"
    elif mode == "tls":
        os.environ["SMTP_USE_SSL"] = "false"; os.environ["SMTP_PORT"] = os.getenv("SMTP_PORT") or "587"

    ok = send_email(to, f"SMTP diag ({mode or 'env default'})",
                    "<b>This is a diagnostic email from Navona.</b>")
    return {
        "ok": ok,
        "mode": ("ssl" if os.getenv("SMTP_USE_SSL", "false").lower() == "true" else "tls"),
        "host": SMTP_HOST,
        "port": os.getenv("SMTP_PORT"),
        "from": SMTP_FROM,
        "to": to
    }, (200 if ok else 500)





@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    credits = user["credits"] if user else 0
    return render_template("user.html", user=user, credits=credits)

# ---------- Logout ----------
@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/")

# ---------- Local dev entry ----------
if __name__ == "__main__":
    print("Serving HTML from:", PAGES_DIR)
    print("Serving CSS  from:", STYLES_DIR)
    app.run(debug=False)
