#!/usr/bin/env python3
"""
==============================================================
 SSO Vulnerability Lab — OAuth 2.0 / OpenID Connect Server
==============================================================
 A fully functional OAuth 2.0 + OIDC authorization server
 with configurable vulnerability modes for lab exercises.

 Standard OAuth Endpoints:
   GET  /.well-known/openid-configuration  — Discovery
   GET  /oauth/authorize                   — Authorization
   POST /oauth/token                       — Token exchange
   GET  /oauth/userinfo                    — UserInfo
   GET  /oauth/jwks                        — JWKS
   GET  /oauth/revoke                      — Revoke (stub)
   GET  /health                            — Health

 Registered clients:
   client_id: vulnerable-client  secret: client-secret-abc123
   client_id: secure-client      secret: secure-secret-xyz789

 Vulnerability flags (env vars):
   VULN_ALLOW_ANY_REDIRECT  — ignore registered redirect_uri
   VULN_SKIP_STATE_CHECK    — don't emit/validate state
   VULN_ACCEPT_NONE_ALG     — accept JWT with alg:none on token endpoint
==============================================================
"""

import os, uuid, time, json, base64, secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse, parse_qs

from flask import Flask, request, redirect, render_template_string, jsonify, make_response
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt          # PyJWT

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "oauth-server-secret")

SERVER_BASE_URL = os.getenv("SERVER_BASE_URL", "http://oauth-server:4000")

# ── Vulnerability flags ───────────────────────────────────────
VULN_ALLOW_ANY_REDIRECT = os.getenv("VULN_ALLOW_ANY_REDIRECT", "true").lower() == "true"
VULN_SKIP_STATE_CHECK   = os.getenv("VULN_SKIP_STATE_CHECK",   "true").lower() == "true"
VULN_ACCEPT_NONE_ALG    = os.getenv("VULN_ACCEPT_NONE_ALG",    "true").lower() == "true"

# ── RSA Key Pair for JWT signing ──────────────────────────────
KEY_FILE = "/tmp/oauth_rsa_key.pem"

def _init_rsa():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
    print("[OAuthServer] Generated new RSA-2048 key for JWT signing")
    return key

RSA_PRIVATE_KEY = _init_rsa()
RSA_PUBLIC_KEY  = RSA_PRIVATE_KEY.public_key()
KID = "lab-key-001"

def _pub_numbers():
    n = RSA_PUBLIC_KEY.public_key() if hasattr(RSA_PUBLIC_KEY, 'public_key') else RSA_PUBLIC_KEY
    pub = n.public_numbers() if hasattr(n,'public_numbers') else RSA_PUBLIC_KEY.public_numbers()
    return pub

# ── Test users ────────────────────────────────────────────────
USERS = {
    "alice@lab.local":     {"password": "alice123",  "role": "admin", "uid": "u001", "name": "Alice Admin",  "email_verified": True},
    "bob@lab.local":       {"password": "bob123",    "role": "user",  "uid": "u002", "name": "Bob User",    "email_verified": True},
    "victim@lab.local":    {"password": "victim123", "role": "user",  "uid": "u003", "name": "Victim",      "email_verified": True},
    "hacker@attacker.com": {"password": "hack123",   "role": "user",  "uid": "u004", "name": "Hacker",      "email_verified": False},
}

# ── Client registry ───────────────────────────────────────────
CLIENTS = {
    "vulnerable-client": {
        "secret":        "client-secret-abc123",
        "redirect_uris": ["http://localhost:5000/lab4/callback",
                          "http://localhost:5000/lab5/callback",
                          "http://localhost:5000/lab6/callback",
                          "http://localhost:5000/lab7/callback"],
        "scopes":        ["openid", "profile", "email"],
        "grant_types":   ["authorization_code"],
    },
    "secure-client": {
        "secret":        "secure-secret-xyz789",
        "redirect_uris": ["http://localhost:5000/secure/callback"],
        "scopes":        ["openid", "profile", "email"],
        "grant_types":   ["authorization_code"],
    },
}

# ── In-memory stores ──────────────────────────────────────────
AUTH_CODES    = {}   # code → {user, client_id, redirect_uri, scope, nonce, expires}
ACCESS_TOKENS = {}   # token → {user, client_id, scope, expires}

def _int_to_b64url(n):
    length = (n.bit_length() + 7) // 8
    b = n.to_bytes(length, 'big')
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# ── JWT helpers ───────────────────────────────────────────────
def issue_access_token(email, client_id, scope, extra_claims=None):
    now = int(time.time())
    payload = {
        "iss":   SERVER_BASE_URL,
        "sub":   USERS[email]["uid"],
        "aud":   client_id,
        "email": email,
        "scope": scope,
        "iat":   now,
        "exp":   now + 3600,
        "jti":   uuid.uuid4().hex,
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, RSA_PRIVATE_KEY, algorithm="RS256",
                       headers={"kid": KID})
    ACCESS_TOKENS[token] = {"email": email, "client_id": client_id,
                             "scope": scope, "exp": now + 3600}
    return token

def issue_id_token(email, client_id, nonce=None, extra_claims=None):
    user = USERS[email]
    now  = int(time.time())
    payload = {
        "iss":            SERVER_BASE_URL,
        "sub":            user["uid"],
        "aud":            client_id,
        "email":          email,
        "email_verified": user["email_verified"],
        "name":           user["name"],
        "role":           user["role"],
        "iat":            now,
        "exp":            now + 3600,
    }
    if nonce:
        payload["nonce"] = nonce
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, RSA_PRIVATE_KEY, algorithm="RS256",
                      headers={"kid": KID})

# ── JWKS ──────────────────────────────────────────────────────
def build_jwks():
    pub = RSA_PUBLIC_KEY.public_numbers()
    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": KID,
            "alg": "RS256",
            "n":   _int_to_b64url(pub.n),
            "e":   _int_to_b64url(pub.e),
        }]
    }

# ── HTML templates ─────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html><html>
<head><title>OAuth Server — Authorize</title>
<style>
body{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0;padding:40px}
.box{max-width:460px;margin:0 auto;background:#161b22;padding:30px;border-radius:8px;border:1px solid #30363d}
h2{color:#58a6ff;margin-top:0}
.app{background:#0d1117;padding:10px;border-radius:5px;margin-bottom:16px}
.scope{color:#8b949e;font-size:13px}
input{width:100%;padding:9px;margin:8px 0;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;box-sizing:border-box}
.btns{display:flex;gap:10px;margin-top:16px}
button{flex:1;padding:10px;border:none;border-radius:5px;cursor:pointer;font-size:14px}
.allow{background:#238636;color:white}.deny{background:#b91c1c;color:white}
.err{color:#f85149;margin:8px 0}
.users{font-size:12px;margin-top:16px;background:#0d1117;padding:10px;border-radius:5px;color:#8b949e}
</style></head>
<body><div class="box">
<h2>🔑 Authorize Application</h2>
<div class="app">
  <b>{{ client_id }}</b> is requesting access to your account.<br>
  <span class="scope">Scopes: {{ scope }}</span>
</div>
{% if error %}<div class="err">⚠ {{ error }}</div>{% endif %}
<input type="email" id="email" placeholder="Email" value="">
<input type="password" id="pass" placeholder="Password">
<div class="btns">
  <button class="allow" onclick="authorize()">Allow</button>
  <button class="deny" onclick="window.location='{{ deny_url }}'">Deny</button>
</div>
<div class="users">
  alice@lab.local / alice123 (admin) &nbsp;|&nbsp;
  bob@lab.local / bob123 (user)<br>
  victim@lab.local / victim123 &nbsp;|&nbsp;
  hacker@attacker.com / hack123
</div>
</div>
<form id="f" method="POST" action="/oauth/authorize">
  <input type="hidden" name="client_id" value="{{ client_id }}">
  <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
  <input type="hidden" name="scope" value="{{ scope }}">
  <input type="hidden" name="state" value="{{ state }}">
  <input type="hidden" name="nonce" value="{{ nonce }}">
  <input type="hidden" name="response_type" value="{{ response_type }}">
  <input type="hidden" name="email" id="hEmail">
  <input type="hidden" name="password" id="hPass">
</form>
<script>
function authorize() {
  document.getElementById('hEmail').value = document.getElementById('email').value;
  document.getElementById('hPass').value  = document.getElementById('pass').value;
  document.getElementById('f').submit();
}
</script>
</body></html>"""

# ── Routes ─────────────────────────────────────────────────────
@app.route("/health")
def health():
    return {"status": "ok", "service": "oauth-server"}, 200

@app.route("/.well-known/openid-configuration")
def discovery():
    return jsonify({
        "issuer":                  SERVER_BASE_URL,
        "authorization_endpoint":  f"{SERVER_BASE_URL}/oauth/authorize",
        "token_endpoint":          f"{SERVER_BASE_URL}/oauth/token",
        "userinfo_endpoint":       f"{SERVER_BASE_URL}/oauth/userinfo",
        "jwks_uri":                f"{SERVER_BASE_URL}/oauth/jwks",
        "response_types_supported":["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported":        ["openid","profile","email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post","client_secret_basic"],
    })

@app.route("/oauth/jwks")
def jwks():
    return jsonify(build_jwks())

@app.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    if request.method == "GET":
        client_id     = request.args.get("client_id", "")
        redirect_uri  = request.args.get("redirect_uri", "")
        scope         = request.args.get("scope", "openid")
        state         = request.args.get("state", "")
        nonce         = request.args.get("nonce", "")
        response_type = request.args.get("response_type", "code")

        client = CLIENTS.get(client_id)
        if not client:
            return jsonify({"error": "unknown_client"}), 400

        # ── redirect_uri validation ───────────────────────────
        if not VULN_ALLOW_ANY_REDIRECT:
            if redirect_uri not in client["redirect_uris"]:
                return jsonify({"error": "invalid_redirect_uri"}), 400
        # else: ⚠️  VULN — accept any redirect_uri

        deny_url = f"{redirect_uri}?error=access_denied&state={state}"
        return render_template_string(LOGIN_HTML,
            client_id=client_id, redirect_uri=redirect_uri, scope=scope,
            state=state, nonce=nonce, response_type=response_type,
            deny_url=deny_url, error=None)

    # POST — process user credentials
    client_id     = request.form.get("client_id", "")
    redirect_uri  = request.form.get("redirect_uri", "")
    scope         = request.form.get("scope", "openid")
    state         = request.form.get("state", "")
    nonce         = request.form.get("nonce", "")
    email         = request.form.get("email", "").strip().lower()
    password      = request.form.get("password", "").strip()

    user = USERS.get(email)
    if not user or user["password"] != password:
        deny_url = f"{redirect_uri}?error=access_denied&state={state}"
        return render_template_string(LOGIN_HTML,
            client_id=client_id, redirect_uri=redirect_uri, scope=scope,
            state=state, nonce=nonce, response_type="code",
            deny_url=deny_url, error="Invalid credentials")

    # Issue auth code
    code = secrets.token_urlsafe(24)
    AUTH_CODES[code] = {
        "email":        email,
        "client_id":    client_id,
        "redirect_uri": redirect_uri,
        "scope":        scope,
        "nonce":        nonce,
        "state":        state,
        "expires":      time.time() + 120,
    }

    params = {"code": code}
    if state:
        params["state"] = state
    return redirect(f"{redirect_uri}?{urlencode(params)}")

@app.route("/oauth/token", methods=["POST"])
def token():
    grant_type    = request.form.get("grant_type", "")
    code          = request.form.get("code", "")
    redirect_uri  = request.form.get("redirect_uri", "")
    client_id     = request.form.get("client_id", "")
    client_secret = request.form.get("client_secret", "")

    # Basic auth fallback
    auth = request.headers.get("Authorization","")
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            pass

    client = CLIENTS.get(client_id)
    if not client or client["secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    entry = AUTH_CODES.pop(code, None)
    if not entry:
        return jsonify({"error": "invalid_grant", "desc": "unknown code"}), 400
    if entry["expires"] < time.time():
        return jsonify({"error": "invalid_grant", "desc": "code expired"}), 400
    if entry["client_id"] != client_id:
        return jsonify({"error": "invalid_grant", "desc": "client mismatch"}), 400

    email = entry["email"]
    scope = entry["scope"]
    nonce = entry["nonce"]

    access_token = issue_access_token(email, client_id, scope)
    id_token     = issue_id_token(email, client_id, nonce)

    return jsonify({
        "access_token": access_token,
        "token_type":   "Bearer",
        "expires_in":   3600,
        "id_token":     id_token,
        "scope":        scope,
    })

@app.route("/oauth/userinfo")
def userinfo():
    auth  = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()

    # Try verifying with RS256 first
    email = None
    try:
        pub_pem = RSA_PUBLIC_KEY.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        payload = jwt.decode(token, pub_pem, algorithms=["RS256"],
                             options={"verify_aud": False})
        email = payload.get("email")
    except Exception:
        # ─────────────────────────────────────────────────────
        # ⚠️  VULN_ACCEPT_NONE_ALG: Also accept alg:none tokens
        # ─────────────────────────────────────────────────────
        if VULN_ACCEPT_NONE_ALG:
            try:
                payload = jwt.decode(token, options={
                    "verify_signature": False,
                    "verify_exp": False
                }, algorithms=["none","RS256","HS256"])
                email = payload.get("email")
            except Exception:
                pass

    if not email or email not in USERS:
        return jsonify({"error": "invalid_token"}), 401

    user = USERS[email]
    return jsonify({
        "sub":            user["uid"],
        "email":          email,
        "email_verified": user["email_verified"],
        "name":           user["name"],
        "role":           user["role"],
    })

@app.route("/oauth/revoke", methods=["POST"])
def revoke():
    token = request.form.get("token","")
    ACCESS_TOKENS.pop(token, None)
    return jsonify({"status": "ok"})

@app.route("/")
def index():
    return jsonify({
        "service": "OAuth 2.0 / OIDC Authorization Server",
        "discovery": f"{SERVER_BASE_URL}/.well-known/openid-configuration",
        "vulns_active": {
            "VULN_ALLOW_ANY_REDIRECT": VULN_ALLOW_ANY_REDIRECT,
            "VULN_SKIP_STATE_CHECK":   VULN_SKIP_STATE_CHECK,
            "VULN_ACCEPT_NONE_ALG":    VULN_ACCEPT_NONE_ALG,
        }
    })

if __name__ == "__main__":
    print(f"[OAuthServer] Starting on port 4000")
    print(f"[OAuthServer] Vulns: ANY_REDIRECT={VULN_ALLOW_ANY_REDIRECT} "
          f"NONE_ALG={VULN_ACCEPT_NONE_ALG}")
    app.run(host="0.0.0.0", port=4000, debug=False)
