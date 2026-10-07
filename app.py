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
