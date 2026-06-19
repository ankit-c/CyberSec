#!/usr/bin/env python3
"""
==============================================================
 SSO Vulnerability Lab — SAML 2.0 Identity Provider
==============================================================
 Issues properly signed SAML 2.0 assertions (RSA-SHA256).
 Used as the trusted IdP for all SAML lab challenges.

 Endpoints:
   GET  /health              — health check
   GET  /saml/metadata       — IdP SAML metadata
   GET  /saml/cert           — IdP public cert (PEM)
   GET  /saml/sso            — Redirect-binding login page
   POST /saml/sso            — Process credentials, issue assertion
   GET  /                    — Lab info page

 Test accounts:
   alice@lab.local   / alice123   → role: admin
   bob@lab.local     / bob123     → role: user
   victim@lab.local  / victim123  → role: user
   hacker@attacker.com / hack123  → role: user
==============================================================
"""

import os, base64, zlib, uuid, hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, parse_qs, urlparse

from flask import Flask, request, redirect, render_template_string, session, make_response
from lxml import etree
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "idp-secret-lab-key")

IDP_BASE_URL  = os.getenv("IDP_BASE_URL", "http://saml-idp:8080")
IDP_ENTITY_ID = f"{IDP_BASE_URL}/saml/metadata"

# ── Test users ──────────────────────────────────────────────
USERS = {
    "alice@lab.local":       {"password": "alice123",  "role": "admin", "uid": "u001", "name": "Alice Admin"},
    "bob@lab.local":         {"password": "bob123",    "role": "user",  "uid": "u002", "name": "Bob User"},
    "victim@lab.local":      {"password": "victim123", "role": "user",  "uid": "u003", "name": "Victim"},
    "hacker@attacker.com":   {"password": "hack123",   "role": "user",  "uid": "u004", "name": "Hacker"},
}

# ── RSA key-pair (generated once at startup) ─────────────────
KEY_FILE  = "/tmp/lab_idp_key.pem"
CERT_FILE = "/tmp/lab_idp_cert.pem"

def _init_crypto():
    if os.path.exists(KEY_FILE) and os.path.exists(CERT_FILE):
        with open(KEY_FILE, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CERT_FILE, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       "Lab SAML IdP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSO Vuln Lab"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("[IdP] Generated new RSA-2048 key pair + self-signed cert")
    return key, cert

PRIVATE_KEY, CERT = _init_crypto()

def _cert_b64():
    pem = CERT.public_bytes(serialization.Encoding.PEM).decode()
    return pem.replace("-----BEGIN CERTIFICATE-----","").replace("-----END CERTIFICATE-----","").replace("\n","")

def _cert_pem():
    return CERT.public_bytes(serialization.Encoding.PEM)

# ── XML Signature helpers (enveloped, RSA-SHA256) ────────────
_NS = {
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
}

def _c14n(element):
    """Return exclusive canonical XML bytes for an element (Signature excluded)."""
    import io
    from lxml.etree import tostring
    # Strip any existing ds:Signature child before canonicalising
    tmp = etree.fromstring(etree.tostring(element))
    for sig in tmp.findall("ds:Signature", _NS):
        tmp.remove(sig)
    buf = io.BytesIO()
    tmp.getroottree().write_c14n(buf, exclusive=True, with_comments=False)
    # write_c14n writes the whole doc — we need just this element
    # Simpler: use tostring with method='c14n'
    return etree.tostring(tmp, method="c14n", exclusive=True)

def _sign_element(element, ref_id):
    """
    Attach an enveloped RSA-SHA256 XML signature to *element*.
    The Signature covers the element identified by ref_id.
    """
    # 1) Canonicalise (excluding Signature placeholder)
    c14n_bytes = _c14n(element)

    # 2) Digest
    digest = hashlib.sha256(c14n_bytes).digest()
    digest_b64 = base64.b64encode(digest).decode()

    # 3) Build SignedInfo canonical form
    signed_info_xml = (
        '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        f'<ds:Reference URI="#{ref_id}">'
        '<ds:Transforms>'
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        '</ds:Transforms>'
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f'<ds:DigestValue>{digest_b64}</ds:DigestValue>'
        '</ds:Reference>'
        '</ds:SignedInfo>'
    )
    si_bytes = etree.tostring(etree.fromstring(signed_info_xml.encode()),
                              method="c14n", exclusive=True)

    # 4) RSA-SHA256 sign the canonical SignedInfo
    sig_bytes = PRIVATE_KEY.sign(si_bytes, asym_padding.PKCS1v15(), hashes.SHA256())
    sig_b64   = base64.b64encode(sig_bytes).decode()
    cert_b64  = _cert_b64()

    # 5) Build the full Signature element
    sig_xml = (
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        + signed_info_xml +
        f'<ds:SignatureValue>{sig_b64}</ds:SignatureValue>'
        '<ds:KeyInfo>'
        '<ds:X509Data>'
        f'<ds:X509Certificate>{cert_b64}</ds:X509Certificate>'
        '</ds:X509Data>'
        '</ds:KeyInfo>'
        '</ds:Signature>'
    )
    sig_el = etree.fromstring(sig_xml.encode())

    # 6) Insert after Issuer (standard position)
    issuer = element.find("saml:Issuer", _NS)
    pos = list(element).index(issuer) + 1 if issuer is not None else 0
    element.insert(pos, sig_el)
    return element

# ── SAML Response builder ────────────────────────────────────
def build_saml_response(email, user, acs_url, request_id,
                        sign_assertion=True, sign_response=False):
    now    = datetime.now(timezone.utc)
    expiry = now + timedelta(minutes=10)
    fmt    = "%Y-%m-%dT%H:%M:%SZ"

    resp_id   = "_" + uuid.uuid4().hex
    assert_id = "_" + uuid.uuid4().hex

    assertion_xml = f"""<saml:Assertion
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="{assert_id}"
      IssueInstant="{now.strftime(fmt)}"
      Version="2.0">
  <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        InResponseTo="{request_id}"
        NotOnOrAfter="{expiry.strftime(fmt)}"
        Recipient="{acs_url}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{now.strftime(fmt)}" NotOnOrAfter="{expiry.strftime(fmt)}">
    <saml:AudienceRestriction>
      <saml:Audience>http://vulnerable-saml-sp:3000</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>{email}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="role">
      <saml:AttributeValue>{user['role']}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="uid">
      <saml:AttributeValue>{user['uid']}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="displayName">
      <saml:AttributeValue>{user['name']}</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"""

    assertion_el = etree.fromstring(assertion_xml.encode())
    if sign_assertion:
        assertion_el = _sign_element(assertion_el, assert_id)

    response_el = etree.fromstring(f"""<samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="{resp_id}"
      InResponseTo="{request_id}"
      Version="2.0"
      IssueInstant="{now.strftime(fmt)}"
      Destination="{acs_url}">
  <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>""".encode())

    response_el.append(assertion_el)
    return etree.tostring(response_el, encoding="unicode"), assert_id

# ── AuthnRequest decoder ─────────────────────────────────────
def decode_authn_request(b64_str):
    try:
        raw = base64.b64decode(b64_str)
        try:
            return zlib.decompress(raw, -15)   # deflate (HTTP-Redirect)
        except Exception:
            return raw                           # raw (HTTP-POST)
    except Exception:
        return None

DEFAULT_ACS = "http://localhost:3000/lab1/acs"

# ── HTML templates ───────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html><html>
<head><title>Lab IdP — Login</title>
<style>
  body{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0}
  .box{max-width:420px;margin:80px auto;background:#161b22;padding:30px;border-radius:8px;border:1px solid #30363d}
  h2{color:#58a6ff;margin-top:0}span.badge{background:#238636;padding:2px 8px;border-radius:4px;font-size:11px}
  input{width:100%;padding:9px;margin:8px 0;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;box-sizing:border-box}
  button{width:100%;padding:10px;background:#238636;border:none;color:white;border-radius:5px;cursor:pointer;font-size:14px}
  .users{font-size:12px;margin-top:16px;background:#0d1117;padding:10px;border-radius:5px;color:#8b949e}
  .err{color:#f85149;margin:8px 0}
</style></head><body>
<div class="box">
  <h2>🔐 Lab IdP <span class="badge">SAML 2.0</span></h2>
  {% if error %}<div class="err">⚠ {{ error }}</div>{% endif %}
  <form method="POST">
    <input type="hidden" name="SAMLRequest" value="{{ saml_request }}">
    <input type="hidden" name="RelayState" value="{{ relay_state }}">
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign In →</button>
  </form>
  <div class="users">
    <b>Test Accounts</b><br>
    alice@lab.local / alice123 &nbsp;→ admin<br>
    bob@lab.local / bob123 &nbsp;→ user<br>
    victim@lab.local / victim123 &nbsp;→ user<br>
    hacker@attacker.com / hack123 &nbsp;→ user
  </div>
</div></body></html>"""

# ── Routes ───────────────────────────────────────────────────
@app.route("/health")
def health():
    return {"status": "ok", "service": "saml-idp"}, 200

@app.route("/")
def index():
    return f"""<h2>Lab SAML IdP</h2>
<ul>
  <li>Metadata: <a href="/saml/metadata">/saml/metadata</a></li>
  <li>Cert: <a href="/saml/cert">/saml/cert</a></li>
  <li>SSO: <a href="/saml/sso">/saml/sso</a></li>
</ul>
<p>Entity ID: <code>{IDP_ENTITY_ID}</code></p>"""

@app.route("/saml/metadata")
def metadata():
    cb = _cert_b64()
    xml = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY_ID}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{cb}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{IDP_BASE_URL}/saml/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{IDP_BASE_URL}/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""
    return make_response(xml, 200, {"Content-Type": "application/xml"})

@app.route("/saml/cert")
def cert():
    return make_response(_cert_pem(), 200, {"Content-Type": "text/plain"})

@app.route("/saml/sso", methods=["GET", "POST"])
def sso():
    if request.method == "GET":
        saml_req  = request.args.get("SAMLRequest", "")
        relay     = request.args.get("RelayState",  "")
        acs_url   = DEFAULT_ACS
        req_id    = "_default"

        xml = decode_authn_request(saml_req)
        if xml:
            try:
                root    = etree.fromstring(xml)
                req_id  = root.get("ID", req_id)
                acs_url = root.get("AssertionConsumerServiceURL", acs_url)
            except Exception:
                pass

        session["req_id"]   = req_id
        session["acs_url"]  = acs_url
        session["relay"]    = relay
        return render_template_string(LOGIN_HTML,
            saml_request=saml_req, relay_state=relay, error=None)

    # POST — process credentials
    email    = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "").strip()
    saml_req = request.form.get("SAMLRequest", "")
    relay    = request.form.get("RelayState", "")

    req_id  = session.get("req_id",  "_default")
    acs_url = session.get("acs_url", DEFAULT_ACS)

    user = USERS.get(email)
    if not user or user["password"] != password:
        return render_template_string(LOGIN_HTML,
            saml_request=saml_req, relay_state=relay,
            error="Invalid credentials")

    resp_xml, _ = build_saml_response(email, user, acs_url, req_id)
    resp_b64    = base64.b64encode(resp_xml.encode()).decode()

    # Auto-submit form back to SP ACS
    html = f"""<!DOCTYPE html><html>
<body onload="document.forms[0].submit()">
<form method="POST" action="{acs_url}">
  <input type="hidden" name="SAMLResponse" value="{resp_b64}">
  <input type="hidden" name="RelayState" value="{relay}">
</form>
<p>Authenticating...</p>
</body></html>"""
    return html

if __name__ == "__main__":
    print(f"[IdP] Starting on port 8080 | Entity: {IDP_ENTITY_ID}")
    app.run(host="0.0.0.0", port=8080, debug=False)
