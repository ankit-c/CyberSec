#!/usr/bin/env python3
"""
==============================================================
 SSO Vulnerability Lab — Vulnerable SAML Service Provider
==============================================================
 IDP_BASE_URL    → container-to-container (cert fetch)
 IDP_BROWSER_URL → browser-visible redirects (always localhost)
 SP_BASE_URL     → browser-visible SP URLs  (always localhost)
==============================================================
"""

import os, base64, zlib, uuid, hashlib, requests
from datetime import datetime, timezone
from urllib.parse import urlencode
from functools import wraps

from flask import (Flask, request, redirect, url_for,
                   render_template_string, session, jsonify)
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "sp-secret-lab-key")

# Internal hostname — container talks to saml-idp container
IDP_BASE_URL    = os.getenv("IDP_BASE_URL",    "http://saml-idp:8080")
# External hostname — browser is redirected here (always localhost)
IDP_BROWSER_URL = os.getenv("IDP_BROWSER_URL", "http://localhost:8080")
# SP's own public URL seen by browser
SP_BASE_URL     = os.getenv("SP_BASE_URL",     "http://localhost:3000")

IDP_ENTITY_ID = f"{IDP_BASE_URL}/saml/metadata"
SP_ENTITY_ID  = "http://vulnerable-saml-sp:3000"

NS = {
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
}

# ── Fetch IdP cert (server-to-server via internal URL) ──────
_IDP_CERT_CACHE = None

def get_idp_cert():
    global _IDP_CERT_CACHE
    if _IDP_CERT_CACHE:
        return _IDP_CERT_CACHE
    try:
        r = requests.get(f"{IDP_BASE_URL}/saml/cert", timeout=5)
        _IDP_CERT_CACHE = r.content
        return _IDP_CERT_CACHE
    except Exception as e:
        print(f"[SP] Could not fetch IdP cert: {e}")
        return None

# ── XML Signature verification ───────────────────────────────
def _c14n(element):
    tmp = etree.fromstring(etree.tostring(element))
    for sig in tmp.findall("ds:Signature", NS):
        tmp.remove(sig)
    return etree.tostring(tmp, method="c14n", exclusive=True)

def _verify_rsa_sha256(cert_pem, signed_info_bytes, signature_b64):
    cert = x509.load_pem_x509_certificate(cert_pem)
    pub  = cert.public_key()
    try:
        pub.verify(
            base64.b64decode(signature_b64),
            signed_info_bytes,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def verify_saml_signature(root, cert_pem):
    sig_el = root.find(".//ds:Signature", NS)
    if sig_el is None:
        return None, None, "No Signature element found"

    ref_el  = sig_el.find(".//ds:Reference", NS)
    if ref_el is None:
        return None, None, "No ds:Reference found"
    ref_uri = ref_el.get("URI", "").lstrip("#")

    signed_el = None
    for el in root.iter():
        if el.get("ID") == ref_uri:
            signed_el = el
            break
    if signed_el is None:
        return None, None, f"Referenced element #{ref_uri} not found"

    si_el = sig_el.find("ds:SignedInfo", NS)
    if si_el is None:
        return None, None, "No SignedInfo"
    si_c14n = etree.tostring(si_el, method="c14n", exclusive=True)

    sig_val = sig_el.findtext("ds:SignatureValue", namespaces=NS)
    if not sig_val:
        return None, None, "No SignatureValue"
    sig_val = sig_val.strip().replace("\n", "")

    digest_el  = ref_el.find("ds:DigestValue", NS)
    digest_val = (digest_el.text or "").strip().replace("\n", "") if digest_el is not None else ""
    elem_c14n  = _c14n(signed_el)
    computed   = base64.b64encode(hashlib.sha256(elem_c14n).digest()).decode()
    if computed != digest_val:
        return None, None, f"DigestValue mismatch"

    if not _verify_rsa_sha256(cert_pem, si_c14n, sig_val):
        return None, None, "RSA signature verification failed"

    return signed_el, ref_uri, None

# ── AuthnRequest builder ─────────────────────────────────────
def build_authn_request(acs_url, sp_entity_id):
    req_id = "_" + uuid.uuid4().hex
    now    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{req_id}" Version="2.0" IssueInstant="{now}"'
        f' AssertionConsumerServiceURL="{acs_url}">'
        f'<saml:Issuer>{sp_entity_id}</saml:Issuer>'
        f'</samlp:AuthnRequest>'
    )
    deflated = zlib.compress(xml.encode())[2:-4]
    b64_req  = base64.b64encode(deflated).decode()
    return req_id, b64_req

def decode_saml_response(b64_resp):
    return base64.b64decode(b64_resp)

def _text(el):
    return el.text.strip() if el is not None and el.text else None

def extract_from_element(el):
    """Secure: read only from the verified/signed element."""
    return {
        "email": _text(el.find(".//saml:NameID", NS)),
        "role":  _text(el.find('.//saml:Attribute[@Name="role"]/saml:AttributeValue', NS)) or "user",
        "name":  _text(el.find('.//saml:Attribute[@Name="displayName"]/saml:AttributeValue', NS)) or "",
    }

def extract_from_root(root):
    """
    ⚠️  VULNERABLE: reads the FIRST matching node anywhere in the
    document tree — not from the verified/signed element.
    An attacker can inject a NameID before the signed assertion.
    """
    name_ids = root.findall(".//saml:NameID", NS)
    roles    = root.findall('.//saml:Attribute[@Name="role"]/saml:AttributeValue', NS)
    names    = root.findall('.//saml:Attribute[@Name="displayName"]/saml:AttributeValue', NS)
    return {
        "email": _text(name_ids[0]) if name_ids else None,
        "role":  _text(roles[0])    if roles    else "user",
        "name":  _text(names[0])    if names    else "Unknown",
    }

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
a{color:#58a6ff}.box{max-width:700px;margin:0 auto}
h1{color:#58a6ff}h2{color:#79c0ff}
.lab{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin:16px 0}
.vuln{color:#f85149;font-weight:bold}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;margin-left:8px}
.red{background:#b91c1c}.yellow{background:#b45309}
a.btn{background:#238636;border:none;color:white;padding:8px 16px;border-radius:5px;
  text-decoration:none;display:inline-block;margin-top:8px}
pre{background:#0d1117;border:1px solid #30363d;padding:12px;border-radius:5px;
  overflow-x:auto;font-size:12px}
</style>"""

INDEX_HTML = BASE_CSS + """
<div class="box">
<h1>🛡 Vulnerable SAML SP</h1>
<div class="lab">
  <h2>Lab 1 — XML Signature Wrapping (XSW) <span class="badge red">CRITICAL</span></h2>
  <p class="vuln">⚠ Verifies signature but reads user data from wrong XML element.</p>
  <a href="/lab1/login" class="btn">Start Lab 1 →</a>
</div>
<div class="lab">
  <h2>Lab 2 — Signature Not Verified <span class="badge red">CRITICAL</span></h2>
  <p class="vuln">⚠ SAML assertion accepted with no signature check at all.</p>
  <a href="/lab2/login" class="btn">Start Lab 2 →</a>
</div>
<div class="lab">
  <h2>Lab 3 — Assertion Replay Attack <span class="badge yellow">HIGH</span></h2>
  <p class="vuln">⚠ Consumed assertion IDs are never recorded. Replay freely.</p>
  <a href="/lab3/login" class="btn">Start Lab 3 →</a>
</div>
</div>"""

DASHBOARD_HTML = BASE_CSS + """
<div class="box">
<h1>✅ Authenticated Dashboard</h1>
<div class="lab">
  <h2>Session Info</h2>
  <pre>Email   : {{ email }}
Role    : {{ role }}
Name    : {{ name }}
Lab     : {{ lab }}
Method  : {{ method }}</pre>
  {% if role == 'admin' %}<p class="vuln">🚨 Admin access granted!</p>{% endif %}
</div>
<a href="/logout" class="btn">Logout</a>&nbsp;<a href="/" class="btn">Back to Labs</a>
</div>"""

ERROR_HTML = BASE_CSS + """
<div class="box"><div class="lab">
<h2 style="color:#f85149">Error</h2>
<pre>{{ msg }}</pre>
<a href="/" class="btn">← Back</a>
</div></div>"""

# ── Routes ───────────────────────────────────────────────────
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
#  LAB 1 — XML Signature Wrapping (XSW)
# ─────────────────────────────────────────────────────────────
@app.route("/lab1/login")
def lab1_login():
    acs = f"{SP_BASE_URL}/lab1/acs"
    req_id, b64_req = build_authn_request(acs, SP_ENTITY_ID)
    session["saml_req_id"] = req_id
    params = urlencode({"SAMLRequest": b64_req, "RelayState": "lab1"})
    # ← Use IDP_BROWSER_URL so YOUR BROWSER can reach the IdP login page
    return redirect(f"{IDP_BROWSER_URL}/saml/sso?{params}")

@app.route("/lab1/acs", methods=["POST"])
def lab1_acs():
    b64_resp = request.form.get("SAMLResponse", "")
    if not b64_resp:
        return render_template_string(ERROR_HTML, msg="Missing SAMLResponse"), 400
    try:
        root = etree.fromstring(decode_saml_response(b64_resp))
    except Exception as e:
        return render_template_string(ERROR_HTML, msg=f"XML parse error: {e}"), 400

    cert_pem = get_idp_cert()
    if not cert_pem:
        return render_template_string(ERROR_HTML, msg="Cannot fetch IdP cert"), 500

    signed_el, signed_id, err = verify_saml_signature(root, cert_pem)
    if err:
        return render_template_string(ERROR_HTML, msg=f"Signature error: {err}"), 401

    # ⚠️  VULNERABLE: reads from root, not from signed_el
    user_data = extract_from_root(root)
    if not user_data["email"]:
        return render_template_string(ERROR_HTML, msg="No email in assertion"), 401

    session["user"] = {
        "email":  user_data["email"],
        "role":   user_data["role"],
        "name":   user_data["name"],
        "lab":    "Lab 1 — XSW",
        "method": f"SAML (signed: #{signed_id}, read: root[0])",
    }
    return redirect("/dashboard")

# ─────────────────────────────────────────────────────────────
#  LAB 2 — No Signature Verification
# ─────────────────────────────────────────────────────────────
@app.route("/lab2/login")
def lab2_login():
    acs = f"{SP_BASE_URL}/lab2/acs"
    req_id, b64_req = build_authn_request(acs, SP_ENTITY_ID)
    session["saml_req_id"] = req_id
    params = urlencode({"SAMLRequest": b64_req, "RelayState": "lab2"})
    return redirect(f"{IDP_BROWSER_URL}/saml/sso?{params}")

@app.route("/lab2/acs", methods=["POST"])
def lab2_acs():
    b64_resp = request.form.get("SAMLResponse", "")
    if not b64_resp:
        return render_template_string(ERROR_HTML, msg="Missing SAMLResponse"), 400
    try:
        root = etree.fromstring(decode_saml_response(b64_resp))
    except Exception as e:
        return render_template_string(ERROR_HTML, msg=f"XML parse error: {e}"), 400

    # ⚠️  VULNERABLE: zero signature verification
    user_data = extract_from_root(root)
    if not user_data["email"]:
        return render_template_string(ERROR_HTML, msg="No email in assertion"), 401

    session["user"] = {
        "email":  user_data["email"],
        "role":   user_data["role"],
        "name":   user_data["name"],
        "lab":    "Lab 2 — No Signature Verification",
        "method": "SAML (⚠ UNVERIFIED — any XML accepted)",
    }
    return redirect("/dashboard")

# ─────────────────────────────────────────────────────────────
#  LAB 3 — Assertion Replay
# ─────────────────────────────────────────────────────────────
@app.route("/lab3/login")
def lab3_login():
    acs = f"{SP_BASE_URL}/lab3/acs"
    req_id, b64_req = build_authn_request(acs, SP_ENTITY_ID)
    session["saml_req_id"] = req_id
    params = urlencode({"SAMLRequest": b64_req, "RelayState": "lab3"})
    return redirect(f"{IDP_BROWSER_URL}/saml/sso?{params}")

@app.route("/lab3/acs", methods=["POST"])
def lab3_acs():
    b64_resp = request.form.get("SAMLResponse", "")
    if not b64_resp:
        return render_template_string(ERROR_HTML, msg="Missing SAMLResponse"), 400
    try:
        root = etree.fromstring(decode_saml_response(b64_resp))
    except Exception as e:
        return render_template_string(ERROR_HTML, msg=f"XML parse error: {e}"), 400

    cert_pem = get_idp_cert()
    if not cert_pem:
        return render_template_string(ERROR_HTML, msg="Cannot fetch IdP cert"), 500

    signed_el, signed_id, err = verify_saml_signature(root, cert_pem)
    if err:
        return render_template_string(ERROR_HTML, msg=f"Signature error: {err}"), 401

    # ⚠️  VULNERABLE: NotOnOrAfter parsed but never enforced
    expiry_el = root.find(".//saml:SubjectConfirmationData", NS)
    not_after = expiry_el.get("NotOnOrAfter") if expiry_el is not None else "unknown"
    # signed_id never added to a seen-set either

    user_data = extract_from_element(signed_el)
    if not user_data["email"]:
        return render_template_string(ERROR_HTML, msg="No email in assertion"), 401

    session["user"] = {
        "email":  user_data["email"],
        "role":   user_data["role"],
        "name":   user_data["name"],
        "lab":    "Lab 3 — Replay Attack",
        "method": f"SAML (replay OK — NotOnOrAfter: {not_after})",
    }
    return redirect("/dashboard")

# ── Debug endpoint used by attack scripts ────────────────────
@app.route("/capture", methods=["POST"])
def capture():
    b64_resp = request.form.get("SAMLResponse", "")
    relay    = request.form.get("RelayState", "")
    if b64_resp:
        xml = decode_saml_response(b64_resp)
        return jsonify({
            "SAMLResponse": b64_resp,
            "RelayState":   relay,
            "decoded_xml":  xml.decode(errors="replace"),
        })
    return jsonify({"error": "No SAMLResponse"}), 400

if __name__ == "__main__":
    print(f"[SP] Starting on :3000")
    print(f"[SP] IDP_BASE_URL (internal) = {IDP_BASE_URL}")
    print(f"[SP] IDP_BROWSER_URL (redirect) = {IDP_BROWSER_URL}")
    print(f"[SP] SP_BASE_URL = {SP_BASE_URL}")
    app.run(host="0.0.0.0", port=3000, debug=False)
