"""
Employee Directory REST API & Web Application
Practical 10: End-to-End DevOps Pipeline (B3-G3: Employee Directory)
"""

import sys
import time
import os
import secrets
import hashlib
import json
import re
import urllib.parse
from datetime import timedelta
import requests
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, request, jsonify, render_template, Response, session, redirect, url_for, send_from_directory, has_request_context
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

basedir = os.path.abspath(os.path.dirname(__file__))
dotenv_path = os.path.join(basedir, ".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    load_dotenv()

app = Flask(__name__)
# Reverse proxy / Vercel compatibility for SSL and host header resolution
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.secret_key = os.environ.get("SECRET_KEY", "devops-employee-directory-secret-key-2026")

# Hardened Session Cookie Configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("VERCEL")),  # HTTPS-only cookie on Vercel; plain http allowed for local dev
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

# Email Format Regex Pattern
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

# Google Cloud OAuth 2.0 Web Client Configuration (None allows os.environ fallback; monkeypatchable in tests)
GOOGLE_CLIENT_ID = None
GOOGLE_CLIENT_SECRET = None
GOOGLE_REDIRECT_URI = None
GOOGLE_SCOPES = None

# GitHub OAuth App Configuration
GITHUB_CLIENT_ID = None
GITHUB_CLIENT_SECRET = None
GITHUB_REDIRECT_URI = None
GITHUB_SCOPES = None

# GitLab OAuth Application Configuration
GITLAB_CLIENT_ID = None
GITLAB_CLIENT_SECRET = None
GITLAB_REDIRECT_URI = None
GITLAB_SCOPES = None


def get_oauth_redirect_uri(provider: str) -> str:
    """
    Dynamically computes or validates the OAuth redirect URI for a provider.
    - If running on a live host (such as Vercel) and the configured URI points to localhost,
      constructs the live canonical URL matching the active request host & scheme.
    - Otherwise returns the configured URI or default local endpoint.
    """
    prefix = provider.upper()
    cur_mod = sys.modules.get(__name__)
    mod_uri = getattr(cur_mod, f"{prefix}_REDIRECT_URI", None)
    configured_uri = (mod_uri if mod_uri is not None else os.environ.get(f"{prefix}_REDIRECT_URI", "")).strip()

    if has_request_context():
        host = request.host.lower()
        is_live_host = "localhost" not in host and "127.0.0.1" not in host
        if configured_uri and is_live_host and ("localhost" in configured_uri or "127.0.0.1" in configured_uri):
            scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
            return f"{scheme}://{request.host}/auth/{provider}/callback"
        if not configured_uri:
            scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
            return f"{scheme}://{request.host}/auth/{provider}/callback"

    if configured_uri:
        return configured_uri
    return f"http://localhost:5001/auth/{provider}/callback"


def get_oauth_config(provider: str):
    """
    Retrieves OAuth credentials and settings for the specified provider ('google', 'github', 'gitlab').
    Prioritizes explicit test monkeypatching while reliably resolving runtime environment variables.
    """
    prefix = provider.upper()
    cur_mod = sys.modules.get(__name__)
    mod_id = getattr(cur_mod, f"{prefix}_CLIENT_ID", None)
    mod_secret = getattr(cur_mod, f"{prefix}_CLIENT_SECRET", None)

    # If explicitly monkeypatched (even to ""), respect the test override; otherwise resolve from os.environ
    if mod_id is not None:
        client_id = mod_id.strip()
    else:
        client_id = os.environ.get(f"{prefix}_CLIENT_ID", "").strip()

    if mod_secret is not None:
        client_secret = mod_secret.strip()
    else:
        client_secret = os.environ.get(f"{prefix}_CLIENT_SECRET", "").strip()

    redirect_uri = get_oauth_redirect_uri(provider)
    scopes = os.environ.get(f"{prefix}_SCOPES", "").strip()
    if not scopes:
        if provider == "google":
            scopes = "openid profile email"
        elif provider == "github":
            scopes = "read:user user:email"
        elif provider == "gitlab":
            scopes = "read_user openid profile email"

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "is_configured": bool(client_id and client_secret)
    }


# In-memory registered users store (Secured with Werkzeug PBKDF2 Password Hashes)
registered_users = {
    "zaid.matinuddin@student.college.edu": {
        "id": 1,
        "name": "Shaikh Zaid Matinuddin",
        "email": "zaid.matinuddin@student.college.edu",
        "password_hash": generate_password_hash("password123"),
        "picture": "/static/logo_text_badge.jpg",
        "role": "CI/CD & Containerization Engineer",
        "department": "Engineering",
        "auth_provider": "local",
        "email_verified": True,
        "created_at": time.time(),
        "last_login_at": time.time()
    }
}
def sanitize_user(user):
    """
    Sanitizes user object by stripping internal password hashes.
    Ensures sensitive credentials are never stored in client sessions or exposed in responses.
    """
    if not user:
        return None
    safe = dict(user)
    safe.pop("password", None)
    safe.pop("password_hash", None)
    return safe

# Prometheus Metrics definition
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP Requests',
    ['method', 'endpoint', 'status']
)
REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP Request Duration in Seconds',
    ['endpoint']
)

# In-memory storage for Employee Directory as required by rubric
employees = [
    {
        "id": 1,
        "name": "SHAIKH RAHMAT",
        "role": "Agile Planner & Documentation Lead (R1)",
        "department": "Platform & Cloud",
        "email": "shaikh.rahmat@student.college.edu",
        "status": "Active",
        "avatar": "SR",
        "location": "Mumbai, India",
        "phone": "+91 98201 11234"
    },
    {
        "id": 2,
        "name": "YADGIR ZUVERIA SALIM",
        "role": "Developer & Version Control (R2)",
        "department": "AI & Data Science",
        "email": "zuveria.yadgir@student.college.edu",
        "status": "Active",
        "avatar": "YZ",
        "location": "Mumbai, India",
        "phone": "+91 98202 22345"
    },
    {
        "id": 3,
        "name": "SHAIKH ZAID MATINUDDIN",
        "role": "CI/CD & Containerization Engineer (R3)",
        "department": "Engineering",
        "email": "zaid.matinuddin@student.college.edu",
        "status": "Active",
        "avatar": "ZM",
        "location": "Mumbai, India",
        "phone": "+91 98203 33456"
    },
    {
        "id": 4,
        "name": "SHAIKH ZAID WAZIDALI",
        "role": "Deployment & Monitoring Engineer (R4)",
        "department": "Core Infrastructure",
        "email": "zaid.wazidali@student.college.edu",
        "status": "Active",
        "avatar": "ZW",
        "location": "Mumbai, India",
        "phone": "+91 98204 44567"
    }
]

next_id = 5


@app.before_request
def start_timer():
    request._start_time = time.time()


@app.after_request
def record_metrics(response):
    if hasattr(request, '_start_time'):
        latency = time.time() - request._start_time
        REQUEST_LATENCY.labels(endpoint=request.path).observe(latency)
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.path,
        status=response.status_code
    ).inc()
    return response


# --- 1. Web UI & Protected Authentication Routes ---
@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"], endpoint="dashboard")
def index():
    user = session.get("user")
    if not user or not isinstance(user, dict) or not user.get("email"):
        session.clear()
        return redirect(url_for("login_page"))
    return render_template("index.html", user=user)


@app.route("/signup", methods=["GET"])
@app.route("/register", methods=["GET"])
@app.route("/login", methods=["GET"])
def login_page():
    user = session.get("user")
    if user and isinstance(user, dict) and user.get("email"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    user = session.get("user")
    if user:
        log_security_event("LOGOUT", "User Logged Out", request.remote_addr or "127.0.0.1", user.get("email", "anonymous"), "Low")
    session.clear()
    return redirect(url_for("login_page"))


# --- 2. Google OAuth 2.0 Web Client Integration ---
@app.route("/auth/google", methods=["GET"])
def auth_google_redirect():
    """
    Initiates real Google OAuth 2.0 Flow.
    Opens legitimate Google account chooser on accounts.google.com with prompt=select_account.
    If unconfigured in environment, redirects to /login?error=oauth_not_configured&provider=google.
    """
    action = request.args.get("action", "signin").strip().lower()
    config = get_oauth_config("google")
    auth_log("google", "INIT", "CONFIG",
             f"client_id_configured={bool(config['client_id'])} secret_configured={bool(config['client_secret'])} redirect_configured={bool(config['redirect_uri'])}")
    if not config["is_configured"]:
        log_security_event("GOOGLE_AUTH_UNCONFIGURED", "Missing Client Credentials", request.remote_addr or "127.0.0.1", "anonymous", "Low")
        auth_log("google", "INIT", "CONFIG_MISSING")
        return redirect(url_for("login_page", error="oauth_not_configured", provider="google"))

    # Generate cryptographically secure random state parameter for CSRF mitigation
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session["oauth_action"] = action

    log_security_event("GOOGLE_AUTH_STARTED", "Initiated", request.remote_addr or "127.0.0.1", "anonymous", "Low")

    auth_params = {
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "response_type": "code",
        "scope": config["scopes"],
        "state": state,
        "access_type": "offline",
        "prompt": "select_account"
    }
    google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(auth_params)}"
    return redirect(google_auth_url)


GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")


def auth_log(provider: str, stage: str, result: str, detail: str = ""):
    """Structured, secret-free OAuth stage logging: [AUTH] provider=google stage=CALLBACK result=SUCCESS"""
    msg = f"[AUTH] provider={provider} stage={stage} result={result}"
    if detail:
        msg += f" detail={detail}"
    print(msg, flush=True)


def google_oauth_fail(code: str, stage: str, detail: str = ""):
    """Logs a classified OAuth failure server-side and redirects with a safe error code."""
    auth_log("google", stage, code, detail)
    return redirect(url_for("login_page", error=code.lower(), provider="google"))


def verify_google_id_token(id_token: str, client_id: str):
    """
    Verifies a Google OIDC ID token server-side via Google's tokeninfo endpoint
    (Google validates the RS256 signature), then enforces issuer, audience and expiry locally.
    Returns the verified claims dict, or None if invalid.
    """
    resp = requests.get("https://oauth2.googleapis.com/tokeninfo", params={"id_token": id_token}, timeout=10)
    if resp.status_code != 200:
        return None
    claims = resp.json()
    if claims.get("iss") not in GOOGLE_ISSUERS:
        return None
    if claims.get("aud") != client_id:
        return None
    try:
        if int(claims.get("exp", 0)) < int(time.time()):
            return None
    except (TypeError, ValueError):
        return None
    if not claims.get("sub"):
        return None
    return claims


@app.route("/auth/google/callback", methods=["GET"])
def auth_google_callback():
    """
    Official Google OAuth 2.0 / OIDC Authorization Callback Handler.
    Validates state, exchanges code for tokens, verifies the ID token (iss/aud/exp/sub),
    cross-checks the UserInfo identity, enforces verified email for account linking,
    and creates the same signed session used by email/password login.
    """
    global next_id
    auth_log("google", "CALLBACK", "RECEIVED")
    error = request.args.get("error")
    if error:
        log_security_event("GOOGLE_AUTH_CANCELLED", f"Consent Denied ({error})", request.remote_addr or "127.0.0.1", "anonymous", "Low")
        log_activity("Google OAuth Cancelled", f"Google authentication was cancelled by the user ({error}).", "Anonymous", "alert-circle", "security")
        if error == "access_denied":
            auth_log("google", "CALLBACK", "ACCESS_DENIED")
            return redirect(url_for("login_page", error="access_denied", provider="google"))
        return google_oauth_fail("OAUTH_PROVIDER_ERROR", "CALLBACK", error[:64])

    # CSRF state verification
    received_state = request.args.get("state", "")
    stored_state = session.pop("oauth_state", None)
    action = session.pop("oauth_action", "signin")

    if not stored_state or not received_state or not secrets.compare_digest(received_state, stored_state):
        log_security_event("GOOGLE_AUTH_FAILED", "State CSRF Mismatch", request.remote_addr or "127.0.0.1", "anonymous", "High")
        auth_log("google", "CALLBACK", "OAUTH_STATE_INVALID")
        return redirect(url_for("login_page", error="invalid_state", provider="google"))

    code = request.args.get("code")
    if not code:
        log_security_event("GOOGLE_AUTH_FAILED", "Missing Authorization Code", request.remote_addr or "127.0.0.1", "anonymous", "Medium")
        auth_log("google", "CALLBACK", "MISSING_CODE")
        return redirect(url_for("login_page", error="missing_code", provider="google"))

    config = get_oauth_config("google")
    if not config["is_configured"]:
        auth_log("google", "CALLBACK", "CONFIG_MISSING")
        return redirect(url_for("login_page", error="oauth_not_configured", provider="google"))

    # Exchange authorization code for tokens via Google Token Endpoint
    try:
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "redirect_uri": config["redirect_uri"],
                "grant_type": "authorization_code"
            },
            headers={"Accept": "application/json"},
            timeout=10
        )
        if token_resp.status_code != 200:
            log_security_event("Token Exchange Failed", "Failed", request.remote_addr or "127.0.0.1", "anonymous", "High")
            try:
                g_err = str(token_resp.json().get("error", ""))[:64]
            except Exception:
                g_err = f"http_{token_resp.status_code}"
            if g_err == "redirect_uri_mismatch":
                return google_oauth_fail("INVALID_REDIRECT_URI", "CODE_EXCHANGE", g_err)
            if g_err == "invalid_client":
                return google_oauth_fail("OAUTH_PROVIDER_ERROR", "CODE_EXCHANGE", g_err)
            return google_oauth_fail("OAUTH_CODE_EXCHANGE_FAILED", "CODE_EXCHANGE", g_err)
        auth_log("google", "CODE_EXCHANGE", "SUCCESS")

        tokens = token_resp.json()
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")
        if not access_token or not id_token:
            return google_oauth_fail("OAUTH_CODE_EXCHANGE_FAILED", "CODE_EXCHANGE", "missing access_token or id_token")

        # Verify OIDC ID token: signature (by Google), issuer, audience, expiry, subject
        claims = verify_google_id_token(id_token, config["client_id"])
        if not claims:
            return google_oauth_fail("GOOGLE_IDENTITY_INVALID", "IDENTITY", "id_token verification failed")

        # Retrieve profile information from Google UserInfo Endpoint
        userinfo_resp = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        if userinfo_resp.status_code != 200:
            return google_oauth_fail("GOOGLE_IDENTITY_INVALID", "IDENTITY", f"userinfo http_{userinfo_resp.status_code}")

        profile = userinfo_resp.json()
    except requests.RequestException as e:
        log_security_event("OAuth Network Error", type(e).__name__, request.remote_addr or "127.0.0.1", "anonymous", "Medium")
        return google_oauth_fail("NETWORK_ERROR", "CODE_EXCHANGE", type(e).__name__)

    google_sub = str(claims.get("sub", ""))
    if str(profile.get("sub", "")) != google_sub:
        return google_oauth_fail("GOOGLE_IDENTITY_INVALID", "IDENTITY", "userinfo sub != id_token sub")

    email = (claims.get("email") or profile.get("email") or "").strip().lower()
    name = profile.get("name", "").strip() or profile.get("given_name", "").strip() or email.split("@")[0].capitalize()
    picture = profile.get("picture", "").strip()
    email_verified = str(claims.get("email_verified", profile.get("email_verified", False))).lower() == "true"

    if not email:
        auth_log("google", "IDENTITY", "MISSING_EMAIL")
        return redirect(url_for("login_page", error="missing_email", provider="google"))
    if not email_verified:
        return google_oauth_fail("GOOGLE_IDENTITY_INVALID", "IDENTITY", "email not verified by Google")
    auth_log("google", "IDENTITY", "SUCCESS")

    user_info = registered_users.get(email)
    if user_info:
        # Account-linking policy: a local account is linked only to a Google identity whose
        # verified email matches; once linked, a different Google subject can never take it over.
        linked_sub = user_info.get("google_sub")
        if linked_sub and linked_sub != google_sub:
            return google_oauth_fail("USER_CREATION_FAILED", "USER", "account already linked to a different Google identity")
        user_info["google_sub"] = google_sub
        user_info["google_email"] = email
        if picture:
            user_info["picture"] = picture
        user_info["email_verified"] = email_verified
        user_info["last_login_at"] = time.time()
        user_info["auth_provider"] = "google+local" if user_info.get("password_hash") else "google"
        log_activity("Google Account Linked", f"User {email} authenticated via Google OAuth 2.0.", name, "shield-check", "security")
        log_security_event("GOOGLE_AUTH_SUCCESS", "Authorized", request.remote_addr or "127.0.0.1", email, "Low")
    else:
        user_info = {
            "id": len(registered_users) + 1,
            "name": name,
            "email": email,
            "google_sub": google_sub,
            "google_email": email,
            "picture": picture,
            "role": "Team Member",
            "department": "Engineering",
            "auth_provider": "google",
            "email_verified": email_verified,
            "created_at": time.time(),
            "last_login_at": time.time()
        }
        registered_users[email] = user_info
        log_activity("Google Account Created", f"Auto-provisioned directory account for {email} via Google OAuth.", name, "user-check", "employee")
        log_security_event("GOOGLE_ACCOUNT_CREATED", "Created", request.remote_addr or "127.0.0.1", email, "Low")
        log_security_event("GOOGLE_AUTH_SUCCESS", "Authorized", request.remote_addr or "127.0.0.1", email, "Low")

    # Ensure employee record exists in Employee Directory list
    existing_emp = next((e for e in employees if e["email"].lower() == email), None)
    if not existing_emp:
        name_parts = name.split()
        avatar = "".join([p[0] for p in name_parts[:2]]).upper() if name_parts else "GU"
        employees.append({
            "id": next_id,
            "name": name.upper(),
            "role": user_info.get("role", "Team Member"),
            "department": user_info.get("department", "Engineering"),
            "email": email,
            "status": "Active",
            "avatar": avatar,
            "location": "Mumbai, India",
            "phone": "+91 98200 12345"
        })
        next_id += 1

    safe_user = sanitize_user(user_info)
    session.permanent = True
    session["user"] = safe_user
    auth_log("google", "SESSION", "SUCCESS")
    return redirect(url_for("dashboard"))


# --- 3. GitHub OAuth 2.0 Integration ---
@app.route("/auth/github", methods=["GET"])
def auth_github_redirect():
    """
    Initiates GitHub OAuth 2.0 authorization flow.
    If unconfigured in environment, redirects to /login?error=oauth_not_configured&provider=github.
    """
    config = get_oauth_config("github")
    if not config["is_configured"]:
        log_security_event("GITHUB_AUTH_UNCONFIGURED", "Missing Client Credentials", request.remote_addr or "127.0.0.1", "anonymous", "Low")
        return redirect(url_for("login_page", error="oauth_not_configured", provider="github"))

    state = secrets.token_urlsafe(32)
    session["github_oauth_state"] = state
    log_security_event("GITHUB_AUTH_STARTED", "Initiated", request.remote_addr or "127.0.0.1", "anonymous", "Low")

    params = {
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "scope": config["scopes"],
        "state": state
    }
    github_url = f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"
    return redirect(github_url)


@app.route("/auth/github/callback", methods=["GET"])
def auth_github_callback():
    """
    GitHub OAuth 2.0 Authorization Callback Handler.
    Exchanges code for access token, fetches authenticated user & email profile,
    links or auto-provisions user, and establishes directory session.
    """
    global next_id
    error = request.args.get("error")
    if error:
        log_security_event("GITHUB_AUTH_CANCELLED", f"Consent Denied ({error})", request.remote_addr or "127.0.0.1", "anonymous", "Low")
        return redirect(url_for("login_page", error="access_denied", provider="github"))

    received_state = request.args.get("state", "")
    stored_state = session.pop("github_oauth_state", None)
    if not stored_state or not received_state or not secrets.compare_digest(received_state, stored_state):
        log_security_event("GITHUB_AUTH_FAILED", "State CSRF Mismatch", request.remote_addr or "127.0.0.1", "anonymous", "High")
        return redirect(url_for("login_page", error="invalid_state", provider="github"))

    code = request.args.get("code")
    if not code:
        log_security_event("GITHUB_AUTH_FAILED", "Missing Authorization Code", request.remote_addr or "127.0.0.1", "anonymous", "Medium")
        return redirect(url_for("login_page", error="missing_code", provider="github"))

    config = get_oauth_config("github")
    try:
        token_resp = requests.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": code,
                "redirect_uri": config["redirect_uri"]
            },
            headers={"Accept": "application/json"},
            timeout=10
        )
        if token_resp.status_code != 200:
            return redirect(url_for("login_page", error="token_exchange_failed", provider="github"))

        tokens = token_resp.json()
        access_token = tokens.get("access_token")
        if not access_token:
            return redirect(url_for("login_page", error="invalid_token_response", provider="github"))

        user_resp = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
            timeout=10
        )
        if user_resp.status_code != 200:
            return redirect(url_for("login_page", error="userinfo_failed", provider="github"))

        profile = user_resp.json()
        # Always resolve the primary VERIFIED email; the public profile email is not verified by GitHub.
        email = None
        emails_resp = requests.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
            timeout=10
        )
        if emails_resp.status_code == 200:
            emails_list = emails_resp.json()
            email = next((e["email"] for e in emails_list if e.get("primary") and e.get("verified")), None)

        if not email:
            return redirect(url_for("login_page", error="missing_email", provider="github"))

        email = email.strip().lower()
        name = profile.get("name") or profile.get("login") or email.split("@")[0].capitalize()
        picture = profile.get("avatar_url") or ""
        github_id = str(profile.get("id"))
    except Exception as e:
        log_security_event("GitHub OAuth Network Error", str(e), request.remote_addr or "127.0.0.1", "anonymous", "Medium")
        return redirect(url_for("login_page", error="network_error", provider="github"))

    user_info = registered_users.get(email)
    if user_info:
        user_info["github_id"] = github_id
        if picture and not user_info.get("picture"):
            user_info["picture"] = picture
        user_info["last_login_at"] = time.time()
        user_info["auth_provider"] = "github+local" if user_info.get("password_hash") else "github"
        log_security_event("GITHUB_AUTH_SUCCESS", "Authorized", request.remote_addr or "127.0.0.1", email, "Low")
    else:
        user_info = {
            "id": len(registered_users) + 1,
            "name": name,
            "email": email,
            "github_id": github_id,
            "picture": picture,
            "role": "Team Member",
            "department": "Engineering",
            "auth_provider": "github",
            "email_verified": True,
            "created_at": time.time(),
            "last_login_at": time.time()
        }
        registered_users[email] = user_info
        log_security_event("GITHUB_ACCOUNT_CREATED", "Created", request.remote_addr or "127.0.0.1", email, "Low")

    # Sync employee directory
    existing_emp = next((e for e in employees if e["email"].lower() == email), None)
    if not existing_emp:
        name_parts = name.split()
        avatar = "".join([p[0] for p in name_parts[:2]]).upper() if name_parts else "GH"
        employees.append({
            "id": next_id,
            "name": name.upper(),
            "role": user_info.get("role", "Team Member"),
            "department": user_info.get("department", "Engineering"),
            "email": email,
            "status": "Active",
            "avatar": avatar,
            "location": "Mumbai, India",
            "phone": "+91 98200 12345"
        })
        next_id += 1

    safe_user = sanitize_user(user_info)
    session.permanent = True
    session["user"] = safe_user
    log_activity("GitHub OAuth Authenticated", f"{name} ({email}) signed in via GitHub.", name, "github", "security")
    return redirect(url_for("dashboard"))


# --- 4. GitLab OAuth 2.0 Integration ---
@app.route("/auth/gitlab", methods=["GET"])
def auth_gitlab_redirect():
    """
    Initiates GitLab OAuth 2.0 authorization flow.
    If unconfigured in environment, redirects to /login?error=oauth_not_configured&provider=gitlab.
    """
    config = get_oauth_config("gitlab")
    if not config["is_configured"]:
        log_security_event("GITLAB_AUTH_UNCONFIGURED", "Missing Client Credentials", request.remote_addr or "127.0.0.1", "anonymous", "Low")
        return redirect(url_for("login_page", error="oauth_not_configured", provider="gitlab"))

    state = secrets.token_urlsafe(32)
    session["gitlab_oauth_state"] = state
    log_security_event("GITLAB_AUTH_STARTED", "Initiated", request.remote_addr or "127.0.0.1", "anonymous", "Low")

    params = {
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "response_type": "code",
        "scope": config["scopes"],
        "state": state
    }
    gitlab_url = f"https://gitlab.com/oauth/authorize?{urllib.parse.urlencode(params)}"
    return redirect(gitlab_url)


@app.route("/auth/gitlab/callback", methods=["GET"])
def auth_gitlab_callback():
    """
    GitLab OAuth 2.0 Authorization Callback Handler.
    """
    global next_id
    error = request.args.get("error")
    if error:
        log_security_event("GITLAB_AUTH_CANCELLED", f"Consent Denied ({error})", request.remote_addr or "127.0.0.1", "anonymous", "Low")
        return redirect(url_for("login_page", error="access_denied", provider="gitlab"))

    received_state = request.args.get("state", "")
    stored_state = session.pop("gitlab_oauth_state", None)
    if not stored_state or not received_state or not secrets.compare_digest(received_state, stored_state):
        log_security_event("GITLAB_AUTH_FAILED", "State CSRF Mismatch", request.remote_addr or "127.0.0.1", "anonymous", "High")
        return redirect(url_for("login_page", error="invalid_state", provider="gitlab"))

    code = request.args.get("code")
    if not code:
        log_security_event("GITLAB_AUTH_FAILED", "Missing Authorization Code", request.remote_addr or "127.0.0.1", "anonymous", "Medium")
        return redirect(url_for("login_page", error="missing_code", provider="gitlab"))

    config = get_oauth_config("gitlab")
    try:
        token_resp = requests.post(
            "https://gitlab.com/oauth/token",
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": config["redirect_uri"]
            },
            headers={"Accept": "application/json"},
            timeout=10
        )
        if token_resp.status_code != 200:
            return redirect(url_for("login_page", error="token_exchange_failed", provider="gitlab"))

        tokens = token_resp.json()
        access_token = tokens.get("access_token")
        if not access_token:
            return redirect(url_for("login_page", error="invalid_token_response", provider="gitlab"))

        user_resp = requests.get(
            "https://gitlab.com/api/v4/user",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        if user_resp.status_code != 200:
            return redirect(url_for("login_page", error="userinfo_failed", provider="gitlab"))

        profile = user_resp.json()
        email = profile.get("email", "").strip().lower()
        if not email:
            return redirect(url_for("login_page", error="missing_email", provider="gitlab"))

        name = profile.get("name") or profile.get("username") or email.split("@")[0].capitalize()
        picture = profile.get("avatar_url") or ""
        gitlab_id = str(profile.get("id"))
    except Exception as e:
        log_security_event("GitLab OAuth Network Error", str(e), request.remote_addr or "127.0.0.1", "anonymous", "Medium")
        return redirect(url_for("login_page", error="network_error", provider="gitlab"))

    user_info = registered_users.get(email)
    if user_info:
        user_info["gitlab_id"] = gitlab_id
        if picture and not user_info.get("picture"):
            user_info["picture"] = picture
        user_info["last_login_at"] = time.time()
        user_info["auth_provider"] = "gitlab+local" if user_info.get("password_hash") else "gitlab"
        log_security_event("GITLAB_AUTH_SUCCESS", "Authorized", request.remote_addr or "127.0.0.1", email, "Low")
    else:
        user_info = {
            "id": len(registered_users) + 1,
            "name": name,
            "email": email,
            "gitlab_id": gitlab_id,
            "picture": picture,
            "role": "Team Member",
            "department": "Engineering",
            "auth_provider": "gitlab",
            "email_verified": True,
            "created_at": time.time(),
            "last_login_at": time.time()
        }
        registered_users[email] = user_info
        log_security_event("GITLAB_ACCOUNT_CREATED", "Created", request.remote_addr or "127.0.0.1", email, "Low")

    # Sync employee directory
    existing_emp = next((e for e in employees if e["email"].lower() == email), None)
    if not existing_emp:
        name_parts = name.split()
        avatar = "".join([p[0] for p in name_parts[:2]]).upper() if name_parts else "GL"
        employees.append({
            "id": next_id,
            "name": name.upper(),
            "role": user_info.get("role", "Team Member"),
            "department": user_info.get("department", "Engineering"),
            "email": email,
            "status": "Active",
            "avatar": avatar,
            "location": "Mumbai, India",
            "phone": "+91 98200 12345"
        })
        next_id += 1

    safe_user = sanitize_user(user_info)
    session.permanent = True
    session["user"] = safe_user
    log_activity("GitLab OAuth Authenticated", f"{name} ({email}) signed in via GitLab.", name, "gitlab", "security")
    return redirect(url_for("dashboard"))


# --- Safe OAuth Diagnostic Endpoint (Phase 9) ---
@app.route("/api/auth/diagnostic", methods=["GET"])
@app.route("/api/auth/oauth-status", methods=["GET"])
def auth_diagnostic():
    """
    Safe OAuth & Identity Configuration Diagnostic.
    Reports configuration status (CONFIGURED / MISSING / INVALID) without leaking secret credentials.
    Usable both locally and in production.
    """
    diagnostics = {}
    for prov in ["google", "github", "gitlab"]:
        cfg = get_oauth_config(prov)
        has_id = bool(cfg["client_id"])
        has_secret = bool(cfg["client_secret"])
        has_redirect = bool(cfg["redirect_uri"])

        if has_id and has_secret and has_redirect:
            prov_status = "CONFIGURED"
        elif not has_id and not has_secret:
            prov_status = "MISSING"
        else:
            prov_status = "INVALID"

        diagnostics[prov] = {
            "client_id_present": "YES" if has_id else "NO",
            "client_secret_present": "YES" if has_secret else "NO",
            "redirect_uri_present": "YES" if has_redirect else "NO",
            "client_id": "CONFIGURED" if has_id else "MISSING",
            "client_secret": "CONFIGURED" if has_secret else "MISSING",
            "redirect_uri": cfg["redirect_uri"] if has_redirect else "MISSING",
            "status": prov_status
        }

    is_vercel = bool(os.environ.get("VERCEL"))
    env_name = os.environ.get("VERCEL_ENV", "production" if is_vercel else "development")

    return jsonify({
        "status": "ok",
        "environment": env_name,
        "is_vercel": is_vercel,
        "base_url": request.host_url.rstrip("/"),
        "providers": diagnostics
    }), 200


@app.route("/api/auth/config-status", methods=["GET"])
def auth_config_status():
    """
    Safe OAuth Provider Configuration Status Diagnostic (Rule #14).
    Reports strictly 'configured' or 'missing' for clientId, clientSecret, and redirectUri.
    Never exposes raw secret values.
    """
    def check_status(val):
        return "configured" if bool(val and str(val).strip()) else "missing"

    result = {}
    for prov in ["google", "github", "gitlab"]:
        cfg = get_oauth_config(prov)
        result[prov] = {
            "clientId": check_status(cfg["client_id"]),
            "clientSecret": check_status(cfg["client_secret"]),
            "redirectUri": check_status(cfg["redirect_uri"])
        }
    return jsonify(result), 200


@app.route("/api/auth/google/status", methods=["GET"])
def auth_google_status():
    """Server-side Google OAuth readiness diagnostic. Returns booleans only - never secrets."""
    cfg = get_oauth_config("google")
    has_id, has_secret, has_redirect = bool(cfg["client_id"]), bool(cfg["client_secret"]), bool(cfg["redirect_uri"])
    return jsonify({
        "provider": "google",
        "clientIdConfigured": has_id,
        "clientSecretConfigured": has_secret,
        "redirectUriConfigured": has_redirect,
        "redirectUri": cfg["redirect_uri"],
        "runtime": "server",
        "environment": os.environ.get("VERCEL_ENV", "development"),
        "oauthReady": has_id and has_secret and has_redirect
    }), 200




# --- 5. Auth API Endpoints (Direct JSON APIs & Session Verification) ---
@app.route("/api/auth/google", methods=["POST"])
@app.route("/api/auth/sso", methods=["POST"])
def auth_sso_disabled():
    """
    SECURITY: These endpoints previously created an authenticated session for ANY email
    supplied in the JSON body (no password, no provider verification) - a full account
    takeover. Identity must come from the verified server-side OAuth/OIDC flow, so
    client-asserted identities are rejected and callers are directed to /auth/<provider>.
    """
    data = request.get_json(silent=True) or {}
    provider = str(data.get("provider", "google")).strip().lower()
    if provider not in ("google", "github", "gitlab"):
        provider = "google"
    log_security_event("SSO_ASSERTION_REJECTED", "Client-asserted identity refused", request.remote_addr or "127.0.0.1", "anonymous", "High")
    auth_log(provider, "INIT", "CLIENT_ASSERTION_REJECTED")
    return jsonify({
        "error": "Use OAuth Redirect Flow",
        "message": "Single Sign-On must be completed through the provider's authorization page.",
        "redirect": f"/auth/{provider}"
    }), 400


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """
    Standard Email / Password Authentication API.
    Validates email format, checks account existence, securely checks password hash,
    and returns authenticated session with dashboard redirect.
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "error": "Validation Error",
            "message": "Email address and password are required."
        }), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({
            "error": "Validation Error",
            "message": "Please enter a valid email address format."
        }), 400

    user = registered_users.get(email)
    if not user:
        return jsonify({
            "error": "Account Not Found",
            "message": "No account found with this email address. Please create an account."
        }), 404

    pwd_hash = user.get("password_hash")
    # Backward compatibility with legacy entries
    if not pwd_hash and "password" in user:
        pwd_hash = generate_password_hash(user.pop("password"))
        user["password_hash"] = pwd_hash

    if not pwd_hash:
        return jsonify({
            "error": "SSO Account",
            "message": "This account was registered using Single Sign-On. Please sign in using your SSO provider."
        }), 400

    if not check_password_hash(pwd_hash, password):
        log_security_event("LOGIN_FAILED", "Incorrect Password", request.remote_addr or "127.0.0.1", email, "Medium")
        return jsonify({
            "error": "Invalid Credentials",
            "message": "Incorrect password. Please verify your credentials and try again."
        }), 401

    user["last_login_at"] = time.time()
    safe_user = sanitize_user(user)
    session.permanent = True
    session["user"] = safe_user

    log_security_event("LOGIN_SUCCESS", "Authorized", request.remote_addr or "127.0.0.1", email, "Low")
    log_activity("User Authenticated", f"{safe_user.get('name')} ({email}) signed in successfully.", safe_user.get('name'), "log-in", "security")

    return jsonify({
        "message": "Login successful",
        "user": safe_user,
        "redirect": "/dashboard"
    }), 200


@app.route("/api/auth/signup", methods=["POST"])
@app.route("/api/auth/register", methods=["POST"])
def auth_signup():
    """
    Standard Account Registration API.
    Validates required fields, password length, confirmation match, duplicate emails,
    hashes password with Werkzeug PBKDF2, provisions user and directory record,
    and returns authenticated session with dashboard redirect.
    """
    global next_id
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    confirm_password = data.get("confirmPassword", "").strip() if "confirmPassword" in data else data.get("confirm_password", "").strip()
    department = data.get("department", "Engineering").strip() or "Engineering"

    if not name or not email or not password:
        return jsonify({
            "error": "Validation Error",
            "message": "Full name, email address, and password are required."
        }), 400

    if len(name) < 2:
        return jsonify({
            "error": "Validation Error",
            "message": "Full name must be at least 2 characters long."
        }), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({
            "error": "Validation Error",
            "message": "Please enter a valid email address format."
        }), 400

    if len(password) < 6:
        return jsonify({
            "error": "Validation Error",
            "message": "Password must be at least 6 characters long."
        }), 400

    if confirm_password and password != confirm_password:
        return jsonify({
            "error": "Validation Error",
            "message": "Passwords do not match. Please verify your confirmation password."
        }), 400

    # Duplicate account detection
    if email in registered_users:
        return jsonify({
            "error": "Duplicate Account",
            "message": "An account with this email address already exists. Please sign in instead."
        }), 409

    # Secure password hashing (Never store plaintext)
    pwd_hash = generate_password_hash(password)
    user_info = {
        "id": len(registered_users) + 1,
        "name": name,
        "email": email,
        "password_hash": pwd_hash,
        "role": "Team Member",
        "department": department,
        "auth_provider": "local",
        "email_verified": True,
        "picture": "",
        "created_at": time.time(),
        "last_login_at": time.time()
    }
    registered_users[email] = user_info

    # Add new registered user directly into employee directory list
    existing = next((e for e in employees if e["email"].lower() == email), None)
    if not existing:
        name_parts = name.split()
        avatar = "".join([p[0] for p in name_parts[:2]]).upper() if name_parts else "EM"
        employees.append({
            "id": next_id,
            "name": name.upper(),
            "role": "Team Member",
            "department": department,
            "email": email,
            "status": "Active",
            "avatar": avatar,
            "location": "Mumbai, India",
            "phone": "+91 98200 00000"
        })
        next_id += 1

    safe_user = sanitize_user(user_info)
    session.permanent = True
    session["user"] = safe_user

    log_security_event("ACCOUNT_CREATED", "Registered", request.remote_addr or "127.0.0.1", email, "Low")
    log_activity("Account Created", f"New user {name} ({email}) created an account.", name, "user-plus", "employee")

    return jsonify({
        "message": "Account created successfully",
        "user": safe_user,
        "redirect": "/dashboard"
    }), 201


@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    user = session.get("user")
    if not user:
        return jsonify({"authenticated": False, "user": None}), 401
    return jsonify({"authenticated": True, "user": sanitize_user(user)}), 200


@app.route("/api/auth/forgot-password", methods=["POST"])
def auth_forgot_password():
    """
    Password Recovery Request API.
    Validates email format, logs security event, and simulates secure recovery dispatch.
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({
            "error": "Validation Error",
            "message": "Email address is required."
        }), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({
            "error": "Validation Error",
            "message": "Please enter a valid email address format."
        }), 400

    log_security_event("PASSWORD_RESET_REQUESTED", "Dispatched", request.remote_addr or "127.0.0.1", email, "Low")
    log_activity("Password Reset Dispatched", f"Recovery instructions requested for {email}.", email.split("@")[0], "key", "security")

    return jsonify({
        "message": f"If an account exists for {email}, password recovery instructions have been sent to your inbox.",
        "success": True
    }), 200



# --- 2. Mandatory Endpoints as specified in Practical Handout ---

@app.route("/health", methods=["GET"])
def health():
    """
    Mandatory Endpoint 1:
    GET /health : returns a simple 'OK' message (used for monitoring checks).
    """
    return jsonify({
        "status": "OK",
        "service": "Employee Directory Service",
        "version": "1.0.0",
        "uptime": "healthy"
    }), 200


@app.route("/items", methods=["GET"])
def get_items():
    """
    Mandatory Endpoint 2:
    GET /items : returns the list of items for the topic (Employee Directory).
    Supports query parameter filtering by department or search term.
    """
    query = request.args.get("search", "").lower()
    dept = request.args.get("department", "").lower()

    filtered = employees
    if query:
        filtered = [
            emp for emp in filtered
            if query in emp["name"].lower() or query in emp["role"].lower() or query in emp["email"].lower()
        ]
    if dept:
        filtered = [emp for emp in filtered if dept == emp["department"].lower()]

    return jsonify(filtered), 200


@app.route("/items", methods=["POST"])
def add_item():
    """
    Mandatory Endpoint 3:
    POST /items : adds a new item to the list.
    """
    global next_id, attendance_roster
    data = request.get_json(silent=True) or request.form.to_dict()

    if not data or not data.get("name") or not data.get("role"):
        return jsonify({
            "error": "Validation Failed",
            "message": "Both 'name' and 'role' are required fields."
        }), 400

    name_parts = data.get("name").strip().split()
    avatar = "".join([p[0] for p in name_parts[:2]]).upper() if name_parts else "EM"

    new_employee = {
        "id": next_id,
        "name": data.get("name").strip(),
        "role": data.get("role").strip(),
        "department": data.get("department", "Engineering").strip(),
        "email": data.get("email", f"{data.get('name').lower().replace(' ', '.')}@student.college.edu").strip(),
        "status": data.get("status", "Active").strip(),
        "avatar": avatar,
        "location": data.get("location", "Mumbai, India").strip(),
        "phone": data.get("phone", "+91 98200 00000").strip()
    }
    employees.append(new_employee)

    # Real-Time Attendance Roster Synchronization
    cur_time = time.strftime("%I:%M %p IST")
    att_status = "Checked In" if new_employee["status"] == "Active" else ("On Leave" if new_employee["status"] == "On Leave" else "Checked Out")
    attendance_entry = {
        "id": next_id,
        "emp_id": next_id,
        "name": new_employee["name"],
        "role": new_employee["role"],
        "department": new_employee["department"],
        "shift": "09:00 AM - 06:00 PM (IST)",
        "shift_type": "Standard Morning Shift",
        "checkin_time": cur_time if att_status == "Checked In" else "—",
        "checkout_time": "—",
        "status": att_status,
        "mode": "Remote (Mumbai - VPN Active)" if att_status == "Checked In" else "Offline",
        "hours_logged": 0.0,
        "target_hours": 8.0,
        "annual_leave_balance": 20,
        "sick_leave_balance": 10,
        "remote_days_used": 0,
        "overtime_hours": 0.0
    }
    if not any(a.get("emp_id") == next_id for a in attendance_roster):
        attendance_roster.append(attendance_entry)

    # Activity Logging for personnel enrollment and attendance shift initialization
    log_activity(
        "New Personnel Enrolled",
        f"{new_employee['name']} registered into directory roster and assigned to {new_employee['department']}.",
        new_employee["name"],
        "user-plus",
        "employee",
        "success",
        "201 Created"
    )
    log_activity(
        "Attendance Shift Assigned",
        f"Standard Morning Shift schedule assigned to {new_employee['name']} ({new_employee['department']}).",
        new_employee["name"],
        "calendar",
        "attendance",
        "info",
        "200 OK"
    )

    next_id += 1

    return jsonify({
        "message": "Employee added successfully",
        "item": new_employee
    }), 201


# --- Additional REST APIs for Professional Experience (Delete & Single item) ---
@app.route("/items/<int:emp_id>", methods=["GET"])
def get_item(emp_id):
    employee = next((e for e in employees if e["id"] == emp_id), None)
    if not employee:
        return jsonify({"error": "Employee not found"}), 404
    return jsonify(employee), 200


@app.route("/items/<int:emp_id>", methods=["DELETE"])
def delete_item(emp_id):
    global employees, attendance_roster
    employee = next((e for e in employees if e["id"] == emp_id), None)
    if not employee:
        return jsonify({"error": "Employee not found"}), 404
    employees = [e for e in employees if e["id"] != emp_id]
    attendance_roster = [a for a in attendance_roster if a.get("emp_id") != emp_id and a.get("id") != emp_id]
    
    # Record activity
    log_activity("Employee Removed", f"Personnel #{emp_id} was removed from the directory.", session.get("user", {}).get("name", "Administrator"), "trash-2", "employee")
    return jsonify({"message": f"Employee {emp_id} deleted successfully"}), 200


# ==============================================================================
# ENTERPRISE DASHBOARD REST API DATA MODELS & ENDPOINTS
# ==============================================================================

activity_logs = [
    {
        "id": 1,
        "title": "New Personnel Enrolled",
        "description": "SHAIKH ZAID WAZIDALI was assigned to Core Infrastructure division.",
        "user": "System Admin",
        "time": "5 minutes ago",
        "timestamp": time.time() - 300,
        "icon": "user-plus",
        "category": "employee",
        "severity": "success",
        "status_code": "201 Created",
        "origin": "127.0.0.1:5001"
    },
    {
        "id": 2,
        "title": "OAuth 2.0 Identity Verified",
        "description": "Session authenticated via Google Identity Services with signed session token.",
        "user": "Shaikh Zaid Matinuddin",
        "time": "12 minutes ago",
        "timestamp": time.time() - 720,
        "icon": "shield-check",
        "category": "security",
        "severity": "success",
        "status_code": "200 OK",
        "origin": "accounts.google.com"
    },
    {
        "id": 3,
        "title": "Prometheus Scrape Sync",
        "description": "Telemetry metrics scrape completed from /metrics endpoint at 15s resolution.",
        "user": "Prometheus Daemon (:9090)",
        "time": "25 minutes ago",
        "timestamp": time.time() - 1500,
        "icon": "activity",
        "category": "system",
        "severity": "info",
        "status_code": "200 OK",
        "origin": "localhost:9090"
    },
    {
        "id": 4,
        "title": "Shift Check-In Logged",
        "description": "SHAIKH ZAID MATINUDDIN clocked in at 08:45 AM IST (On-Premises / Lab).",
        "user": "SHAIKH ZAID MATINUDDIN",
        "time": "40 minutes ago",
        "timestamp": time.time() - 2400,
        "icon": "check-circle",
        "category": "attendance",
        "severity": "success",
        "status_code": "200 OK",
        "origin": "DevOps Lab - Room 402"
    },
    {
        "id": 5,
        "title": "Role Permission Matrix Audit",
        "description": "RBAC verification completed for 4 active personnel records (R1–R4 leads).",
        "user": "Security Lead",
        "time": "1 hour ago",
        "timestamp": time.time() - 3600,
        "icon": "lock",
        "category": "security",
        "severity": "info",
        "status_code": "200 OK",
        "origin": "Internal RBAC Gate"
    },
    {
        "id": 6,
        "title": "VPN Remote Tunnel Initialized",
        "description": "SHAIKH RAHMAT established encrypted VPN tunnel from Mumbai remote node.",
        "user": "SHAIKH RAHMAT",
        "time": "2 hours ago",
        "timestamp": time.time() - 7200,
        "icon": "laptop",
        "category": "attendance",
        "severity": "info",
        "status_code": "200 OK",
        "origin": "Remote (Mumbai - VPN)"
    },
    {
        "id": 7,
        "title": "Grafana Visualizer Handshake",
        "description": "Grafana dashboard (:3000) telemetry connection verified against Prometheus.",
        "user": "Grafana Agent",
        "time": "3 hours ago",
        "timestamp": time.time() - 10800,
        "icon": "layout-grid",
        "category": "system",
        "severity": "info",
        "status_code": "200 OK",
        "origin": "localhost:3000"
    }
]

security_events = [
    {
        "id": "SEC-4091",
        "event": "Google OAuth Token Exchange",
        "status": "Verified",
        "ip": "192.168.1.104",
        "user": "szaid8364@gmail.com",
        "timestamp": "Today at 02:18",
        "severity": "Low"
    },
    {
        "id": "SEC-4090",
        "event": "Prometheus Telemetry Probe",
        "status": "Healthy",
        "ip": "127.0.0.1:9090",
        "user": "prometheus-agent",
        "timestamp": "Today at 02:15",
        "severity": "Info"
    },
    {
        "id": "SEC-4089",
        "event": "Encrypted Session Created",
        "status": "Success",
        "ip": "127.0.0.1",
        "user": "zaid.matinuddin",
        "timestamp": "Today at 02:10",
        "severity": "Low"
    },
    {
        "id": "SEC-4088",
        "event": "Grafana Dashboard Handshake",
        "status": "Authorized",
        "ip": "127.0.0.1:3000",
        "user": "admin",
        "timestamp": "Today at 02:00",
        "severity": "Low"
    }
]

notifications = [
    {
        "id": 1,
        "title": "Security Audit Passed",
        "message": "All session tokens and role permissions are encrypted.",
        "time": "10m ago",
        "read": False,
        "category": "Security",
        "type": "success"
    },
    {
        "id": 2,
        "title": "Directory Synchronized",
        "message": "In-memory database synced with active division records.",
        "time": "30m ago",
        "read": False,
        "category": "Employee",
        "type": "info"
    },
    {
        "id": 3,
        "title": "Telemetry Pipeline Up",
        "message": "Prometheus (:9090) scraping /metrics with 0 dropped samples.",
        "time": "1h ago",
        "read": True,
        "category": "System",
        "type": "info"
    }
]


def log_activity(title, description, user, icon="activity", category="system", severity="info", status_code="200 OK", origin="127.0.0.1:5001"):
    global activity_logs
    activity_logs.insert(0, {
        "id": len(activity_logs) + 1,
        "title": title,
        "description": description,
        "user": user,
        "time": "Just now",
        "timestamp": time.time(),
        "icon": icon,
        "category": category,
        "severity": severity,
        "status_code": status_code,
        "origin": origin
    })
    if len(activity_logs) > 30:
        activity_logs = activity_logs[:30]


def log_security_event(event, status, ip, user, severity="Low"):
    global security_events
    sec_id = f"SEC-{secrets.randbelow(9000) + 1000}"
    security_events.insert(0, {
        "id": sec_id,
        "event": event,
        "status": status,
        "ip": ip,
        "user": user,
        "timestamp": "Just now",
        "severity": severity
    })
    if len(security_events) > 25:
        security_events = security_events[:25]



# --- 1. Dashboard Summary KPI Endpoint ---
@app.route("/api/dashboard/summary", methods=["GET"])
def get_dashboard_summary():
    total_emp = len(employees)
    active_emp = len([e for e in employees if e.get("status", "Active") == "Active"])
    on_leave_emp = len([e for e in employees if e.get("status") == "On Leave"])
    inactive_emp = len([e for e in employees if e.get("status") == "Inactive"])
    depts = len(set([e.get("department", "Engineering") for e in employees]))
    
    return jsonify({
        "totalEmployees": total_emp,
        "totalEmployeesGrowth": "+8.4%",
        "activeEmployees": active_emp,
        "activeEmployeesGrowth": "+5.2%",
        "onLeaveEmployees": on_leave_emp,
        "inactiveEmployees": inactive_emp,
        "totalDepartments": depts,
        "departmentsGrowth": "+2",
        "systemUptime": "99.9%",
        "uptimeTrend": "+0.1%",
        "securityEventsCount": len(security_events),
        "securityTrend": "-12.4%",
        "activeSessions": 86,
        "sessionsGrowth": "+14.2%"
    }), 200


# --- 2. Dashboard Analytics Charts Endpoint ---
@app.route("/api/dashboard/analytics", methods=["GET"])
def get_dashboard_analytics():
    time_range = request.args.get("range", "30d").lower()
    
    # Department Distribution calculation
    dept_counts = {}
    for emp in employees:
        d = emp.get("department", "Engineering")
        dept_counts[d] = dept_counts.get(d, 0) + 1

    # Time-range dynamic growth profiles
    if time_range == "7d":
        growth_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        growth_employees = [4, 4, 4, 4, len(employees), len(employees), len(employees)]
        growth_hires = [0, 0, 0, 0, 1, 0, 0]
        velocity_labels = ["Sprint 38.1", "Sprint 38.2", "Sprint 38.3", "Sprint 38.4", "Sprint 39.1"]
        velocity_points = [36, 40, 38, 42, 45]
        bugs_resolved = [12, 15, 14, 18, 20]
    elif time_range == "90d":
        growth_labels = ["Aug", "Sep", "Oct", "Nov", "Dec", "Jan"]
        growth_employees = [3, 3, 4, 4, 4, len(employees)]
        growth_hires = [0, 0, 1, 0, 0, 1]
        velocity_labels = ["Sprint 35", "Sprint 36", "Sprint 37", "Sprint 38", "Sprint 39"]
        velocity_points = [30, 34, 38, 42, 46]
        bugs_resolved = [8, 11, 14, 17, 21]
    elif time_range == "1y":
        growth_labels = ["Q1", "Q2", "Q3", "Q4", "Q1 '27"]
        growth_employees = [2, 3, 4, 4, len(employees)]
        growth_hires = [1, 1, 1, 0, 1]
        velocity_labels = ["Sprint 31", "Sprint 33", "Sprint 35", "Sprint 37", "Sprint 39"]
        velocity_points = [25, 30, 35, 40, 45]
        bugs_resolved = [6, 10, 14, 18, 22]
    else:  # Default 30d
        growth_labels = ["Week 1", "Week 2", "Week 3", "Week 4", "Current"]
        growth_employees = [3, 3, 4, 4, len(employees)]
        growth_hires = [0, 0, 1, 0, 0]
        velocity_labels = ["Sprint 35", "Sprint 36", "Sprint 37", "Sprint 38", "Sprint 39"]
        velocity_points = [32, 35, 39, 42, 44]
        bugs_resolved = [9, 12, 15, 18, 20]

    return jsonify({
        "timeRange": time_range,
        "metrics": {
            "averageTenure": "2.4 Yrs",
            "tenureGrowth": "+12% YoY",
            "turnoverRate": "0.0%",
            "turnoverStatus": "Optimal stability",
            "complianceRate": "100%",
            "complianceDetails": "All R1–R4 signed",
            "scrapeLatency": "1.2 ms",
            "scrapeStatus": "Prometheus Active",
            "teamVelocity": "42 SP",
            "velocityGrowth": "+18% throughput",
            "codeReviewSLA": "1.8 hrs",
            "slaCompliance": "94% < 4h SLA"
        },
        "kpis": [
            {"id": "kpi-sprint", "name": "Sprint Completion Rate", "value": 98, "target": "100%", "detail": "48 / 49 Tasks Delivered", "color": "indigo"},
            {"id": "kpi-sec", "name": "Security Training & SOC-2 Compliance", "value": 100, "target": "100%", "detail": "4 / 4 R-Series Leads Signed", "color": "emerald"},
            {"id": "kpi-sla", "name": "Code Review SLA (< 4h)", "value": 94, "target": "90%", "detail": "Avg SLA Response: 1.8 hrs", "color": "cyan"},
            {"id": "kpi-ci", "name": "DevOps CI/CD Pipeline Uptime", "value": 99.9, "target": "99.9%", "detail": "GitHub Actions & Runners Active", "color": "purple"},
            {"id": "kpi-cov", "name": "Test Suite Code Coverage", "value": 96.5, "target": "90%", "detail": "16 / 16 Pytest Suites Passing", "color": "teal"}
        ],
        "growth": {
            "labels": growth_labels,
            "employees": growth_employees,
            "newHires": growth_hires,
            "departures": [0] * len(growth_labels)
        },
        "velocity": {
            "labels": velocity_labels,
            "storyPoints": velocity_points,
            "bugsResolved": bugs_resolved
        },
        "departments": {
            "labels": list(dept_counts.keys()),
            "data": list(dept_counts.values())
        }
    }), 200


# --- 3. Enhanced Employee Listing with Sorting, Filtering & Pagination ---
@app.route("/api/employees", methods=["GET"])
def api_get_employees():
    query = request.args.get("search", "").lower()
    dept = request.args.get("department", "").lower()
    status = request.args.get("status", "").lower()
    sort_by = request.args.get("sort_by", "id")
    order = request.args.get("order", "asc")
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 25))

    filtered = employees

    if query:
        filtered = [
            e for e in filtered
            if query in e.get("name", "").lower()
            or query in e.get("role", "").lower()
            or query in e.get("email", "").lower()
            or query in f"emp-{e.get('id'):03d}".lower()
        ]
    if dept:
        filtered = [e for e in filtered if dept == e.get("department", "").lower()]
    if status:
        filtered = [e for e in filtered if status == e.get("status", "").lower()]

    # Sorting
    reverse = (order.lower() == "desc")
    if sort_by in ["id", "name", "role", "department", "status"]:
        filtered = sorted(filtered, key=lambda x: x.get(sort_by, ""), reverse=reverse)

    total = len(filtered)
    start = (page - 1) * limit
    end = start + limit
    paginated_data = filtered[start:end]

    return jsonify({
        "data": paginated_data,
        "pagination": {
            "total": total,
            "page": page,
            "limit": limit,
            "totalPages": max(1, (total + limit - 1) // limit)
        }
    }), 200


# --- 4. Single Employee GET / PUT / DELETE ---
@app.route("/api/employees/<int:emp_id>", methods=["GET", "PUT", "DELETE"])
def api_single_employee(emp_id):
    global employees, attendance_roster
    employee = next((e for e in employees if e["id"] == emp_id), None)
    if not employee:
        return jsonify({"error": "Employee not found"}), 404

    if request.method == "GET":
        return jsonify(employee), 200

    elif request.method == "PUT":
        data = request.get_json(silent=True) or {}
        if "name" in data and data["name"].strip():
            employee["name"] = data["name"].strip()
            name_parts = employee["name"].split()
            employee["avatar"] = "".join([p[0] for p in name_parts[:2]]).upper() if name_parts else "EM"
        if "role" in data and data["role"].strip():
            employee["role"] = data["role"].strip()
        if "department" in data and data["department"].strip():
            employee["department"] = data["department"].strip()
        if "email" in data and data["email"].strip():
            employee["email"] = data["email"].strip()
        if "status" in data and data["status"].strip():
            employee["status"] = data["status"].strip()
        if "location" in data:
            employee["location"] = data["location"].strip()
        if "phone" in data:
            employee["phone"] = data["phone"].strip()

        log_activity("Employee Profile Updated", f"Updated details for {employee['name']}.", session.get("user", {}).get("name", "Administrator"), "edit-3", "employee")
        # Sync attendance roster if present
        for att in attendance_roster:
            if att.get("emp_id") == emp_id or att.get("id") == emp_id:
                att["name"] = employee["name"]
                att["role"] = employee["role"]
                att["department"] = employee["department"]
                if employee["status"] == "On Leave":
                    att["status"] = "On Leave"
                elif employee["status"] == "Active" and att["status"] not in ["Checked In", "Checked Out"]:
                    att["status"] = "Checked In"
        return jsonify({"message": "Employee updated successfully", "item": employee}), 200

    elif request.method == "DELETE":
        employees = [e for e in employees if e["id"] != emp_id]
        attendance_roster = [a for a in attendance_roster if a.get("emp_id") != emp_id and a.get("id") != emp_id]
        log_activity("Employee Removed", f"Personnel #{emp_id} deleted from directory.", session.get("user", {}).get("name", "Administrator"), "trash-2", "employee")
        return jsonify({"message": f"Employee {emp_id} deleted successfully"}), 200


# --- 5. Departments Breakdown Endpoint ---
@app.route("/api/departments", methods=["GET"])
def api_get_departments():
    departments = {}
    for emp in employees:
        d = emp.get("department", "Engineering")
        if d not in departments:
            departments[d] = {
                "name": d,
                "code": "".join([w[0] for w in d.split()]).upper(),
                "headCount": 0,
                "lead": emp.get("name", "TBD"),
                "status": "Active"
            }
        departments[d]["headCount"] += 1

    return jsonify(list(departments.values())), 200