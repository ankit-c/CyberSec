# SSO Lab — Getting Started (Complete Access Guide)

## Why the Original Setup Had a Problem

Docker uses two separate name-resolution systems:

```
Container → Container:   uses service names    (saml-idp, oauth-server)
Browser   → Container:   uses localhost + port  (localhost:8080, localhost:4000)
```

When the SAML SP redirected your browser to the IdP it said:
  "Go to http://saml-idp:8080/saml/sso"
Your browser can't resolve "saml-idp" — that name only works inside Docker.

**The fix (already applied):** The SP now uses two separate URL vars:
- `IDP_BASE_URL=http://saml-idp:8080`    → server fetches IdP cert internally
- `IDP_BROWSER_URL=http://localhost:8080` → browser is redirected here

No /etc/hosts changes needed. Everything works on localhost.

---

## Step 1 — Prerequisites

```bash
# Verify Docker is running
docker --version          # needs 20.10+
docker compose version    # needs v2 (comes with Docker Desktop)

# On Linux if docker compose v2 is missing:
sudo apt install docker-compose-plugin   # Ubuntu/Debian
# OR
sudo yum install docker-compose-plugin   # RHEL/Fedora
```

---

## Step 2 — Start the Lab

```bash
# Extract the zip
unzip sso-vuln-lab.zip
cd sso-vuln-lab

# Make setup script executable
chmod +x setup.sh

# Build images and start all 4 containers (~3 min first time)
./setup.sh start
```

Expected output:
```
[*] Checking dependencies...
  ✓ docker found
  ✓ docker compose found
[*] Building Docker images...
[*] Starting all lab services...
[*] Waiting for services to be healthy...
  [8/30] Waiting...
  ✓ All services healthy

Lab services are running!

Service URLs:
  SAML IdP              http://localhost:8080
  SAML SP (Labs 1-3)    http://localhost:3000
  OAuth Server          http://localhost:4000
  OAuth Client (4-7)    http://localhost:5000
```

---

## Step 3 — Verify Everything Is Running

Open a terminal and run these health checks:

```bash
# Check all 4 services respond
curl -s http://localhost:8080/health   # {"status":"ok","service":"saml-idp"}
curl -s http://localhost:4000/health   # {"status":"ok","service":"oauth-server"}
curl -s http://localhost:3000/         # HTML page with lab links
curl -s http://localhost:5000/         # HTML page with lab links

# Check container status
docker ps
# Should see 4 containers: sso-lab-saml-idp, sso-lab-saml-sp,
#                          sso-lab-oauth-server, sso-lab-oauth-client
```

---

## Step 4 — Access the Labs in Your Browser

Open these URLs directly in your browser — no hosts file changes needed:

### SAML Labs (Labs 1, 2, 3)
```
http://localhost:3000
```
→ Main menu showing all 3 SAML labs with Start buttons

### OAuth / OIDC Labs (Labs 4, 5, 6, 7)
```
http://localhost:5000
```
→ Main menu showing all 4 OAuth labs with Start buttons

### Supporting Services (for inspection / Burp)
```
http://localhost:8080/saml/metadata    ← IdP SAML metadata XML
http://localhost:8080/saml/cert        ← IdP signing certificate
http://localhost:4000/.well-known/openid-configuration   ← OIDC discovery
http://localhost:4000/oauth/jwks       ← JWT public keys (JWKS)
```

---

## Step 5 — Lab-by-Lab Walkthrough

### LAB 1 — SAML XML Signature Wrapping (XSW)

**Goal:** Log in as `alice@lab.local` (admin) using only `hacker@attacker.com` credentials.

**Manual steps (browser + Burp):**

1. Open Burp Suite → enable proxy → set browser to use Burp
2. Visit `http://localhost:3000/lab1/login` in browser
3. You get redirected to `http://localhost:8080/saml/sso` (the IdP login page)
4. Log in as `hacker@attacker.com` / `hack123`
5. In Burp, intercept the POST to `http://localhost:3000/lab1/acs`
6. Send to Repeater — you'll see `SAMLResponse=<base64 blob>`
7. Base64-decode it, see the XML with `hacker@attacker.com`
8. Install SAML Raider extension → go to SAML Raider tab → select XSW Type 2
9. Click "Apply XSW" → change the outer NameID to `alice@lab.local`
10. Forward → dashboard shows alice@lab.local with role: admin ✓

**Automated attack script:**
```bash
python3 attacks/lab1_xsw.py
```

---

### LAB 2 — Signature Not Verified

**Goal:** Authenticate as admin by sending a completely forged XML assertion.

**Manual steps:**

1. Run the attack script — it crafts and submits forged XML directly:
```bash
python3 attacks/lab2_sig_bypass.py alice@lab.local admin
```

**Manual Burp steps:**
1. Visit `http://localhost:3000/lab2/login`, log in as `bob@lab.local` / `bob123`
2. Intercept POST to `/lab2/acs` in Burp
3. Base64-decode the `SAMLResponse`
4. Edit `<saml:NameID>` → change to `alice@lab.local`
5. Edit `<saml:AttributeValue>` for role → change to `admin`
6. Delete the entire `<ds:Signature>...</ds:Signature>` block
7. Re-base64-encode → paste back → Forward
8. Dashboard shows alice@lab.local / admin with no signature needed ✓

---

### LAB 3 — SAML Assertion Replay

**Goal:** Re-use a captured SAML response to authenticate without credentials.

**Steps:**

1. Visit `http://localhost:3000/lab3/login`, log in as `bob@lab.local` / `bob123`
2. In Burp history, find POST to `/lab3/acs` — copy the raw `SAMLResponse` value
3. Log out
4. Using curl or the attack script, replay the same SAMLResponse:

```bash
# Manual replay with curl
curl -X POST http://localhost:3000/lab3/acs \
     -d "SAMLResponse=<PASTE_COPIED_VALUE_HERE>&RelayState=replay" \
     -L -c /tmp/cookies.txt
# Should see 200 on /dashboard — replayed successfully

# Automated
python3 attacks/lab3_replay.py bob@lab.local bob123
```

5. Note: the `NotOnOrAfter` expiry in the assertion is completely ignored ✓

---

### LAB 4 — OAuth CSRF (Missing State)

**Goal:** Understand how missing `state` enables CSRF account takeover.

**Steps:**

1. Visit `http://localhost:5000/lab4/csrf_poc` — this generates the CSRF attack URL
2. Click "Simulate victim click" — it completes the OAuth flow without state check
3. Notice: the callback URL `/lab4/callback` never validates any state parameter

**Automated:**
```bash
python3 attacks/lab4_oauth_csrf.py
```

**What to look for in Burp:**
- GET `/lab4/login` redirect → check the auth URL has no `state=` parameter
- Compare with Lab 5 which has `state=` but still has redirect_uri bug

---

### LAB 5 — Open redirect_uri

**Goal:** Steal an authorization code by injecting attacker-controlled redirect_uri.

**Steps:**

1. Visit this URL (redirect_uri points to attacker's steal endpoint):
```
http://localhost:5000/lab5/login?redirect_uri=http://localhost:5000/lab5/steal
```
2. Log in as any user at the OAuth server
3. Instead of going to the normal callback, the code is sent to `/lab5/steal`
4. `/lab5/steal` automatically exchanges the stolen code for tokens
5. Dashboard shows the victim's identity ✓

**Automated:**
```bash
python3 attacks/lab5_redirect_uri.py
```

---

### LAB 6 — JWT alg:none

**Goal:** Forge a JWT token for alice@lab.local (admin) without the private key.

**Steps — Forge directly:**

1. Visit the forge endpoint:
```
http://localhost:5000/lab6/forge?email=alice@lab.local&role=admin
```
2. Copy the forged JWT token shown on the page
3. Test it against the userinfo endpoint:
```bash
curl -H "Authorization: Bearer <FORGED_TOKEN>" \
     http://localhost:4000/oauth/userinfo
# Returns: {"email":"alice@lab.local","role":"admin",...}
```

**Steps — Through the full flow:**
1. Visit `http://localhost:5000/lab6/login`, log in as any user
2. In Burp, intercept the response from `/oauth/token`
3. Replace the `id_token` value with your forged alg:none JWT
4. Forward → client accepts it → logged in as alice@lab.local ✓

**Automated:**
```bash
python3 attacks/lab6_jwt_none.py alice@lab.local admin
```

---

### LAB 7 — SSO Account Takeover via Email Trust

**Goal:** Log in as `victim@lab.local` using `hacker@attacker.com` credentials.

**Steps:**

1. Visit `http://localhost:5000/lab7/login`
2. At the OAuth server login page, enter: `hacker@attacker.com` / `hack123`
3. The OAuth server returns `email_verified: false` for this account
4. The callback at `/lab7/callback` reads this email, finds no match in APP_USERS
   (hacker@attacker.com doesn't exist locally)
5. The ATO scenario: **in a real target**, register `victim@lab.local` on the IdP
   → the callback finds the existing local account and links it

**To see the warning:**
- Login as `hacker@attacker.com` — dashboard shows `email_verified=False` warning
- The code path that does the ATO is: `APP_USERS.get(idp_email)` — if that email
  exists in the app's DB, it gets linked regardless of `email_verified`

**Automated:**
```bash
python3 attacks/lab7_account_takeover.py
```

---

## Step 6 — Run All Attacks Automatically

```bash
./setup.sh attack
# Runs all 7 attack scripts in sequence
```

---

## Useful Commands

```bash
# View logs from a specific service
./setup.sh logs saml-idp
./setup.sh logs vulnerable-saml-sp
./setup.sh logs oauth-server
./setup.sh logs vulnerable-oauth-client

# Check container status
./setup.sh status

# Restart everything (e.g. after editing source)
./setup.sh restart

# Stop the lab
./setup.sh stop

# Destroy everything (remove images too)
./setup.sh clean
```

---

## Burp Suite Setup for This Lab

```
1. Burp Suite → Proxy → Options → Proxy Listeners
   Add listener: 127.0.0.1:8888

2. Browser proxy settings:
   HTTP proxy: 127.0.0.1:8888

3. Burp → Proxy → Intercept → OFF
   (use HTTP history to review traffic, intercept only when needed)

4. Add to Burp's scope:
   http://localhost:3000
   http://localhost:4000
   http://localhost:5000
   http://localhost:8080

5. Install SAML Raider from BApp Store (for Lab 1 XSW attacks)
6. Install JWT Editor from BApp Store (for Lab 6 alg:none / key confusion)
```

---

## Test Credentials Summary

| Email | Password | Role | email_verified | Use in |
|-------|----------|------|---------------|--------|
| `alice@lab.local` | `alice123` | admin | true | Normal login (target identity) |
| `bob@lab.local` | `bob123` | user | true | Normal login |
| `victim@lab.local` | `victim123` | user | true | Target for ATO demos |
| `hacker@attacker.com` | `hack123` | user | **false** | Attacker account (Labs 1-7) |

---

## Traffic Flow Diagram

```
YOUR BROWSER                    DOCKER NETWORK
     │                               │
     │  GET localhost:3000/lab1/login│
     │──────────────────────────────►│ vulnerable-saml-sp:3000
     │                               │
     │  302 → localhost:8080/saml/sso│ (IDP_BROWSER_URL = localhost)
     │◄──────────────────────────────│
     │                               │
     │  GET localhost:8080/saml/sso  │
     │──────────────────────────────►│ saml-idp:8080
     │  [login form shown]           │
     │◄──────────────────────────────│
     │                               │
     │  POST localhost:8080/saml/sso │
     │  (email + password)           │
     │──────────────────────────────►│ saml-idp:8080
     │                               │  [signs SAML assertion with RSA key]
     │  200 HTML auto-submit form    │
     │  action=localhost:3000/acs    │
     │◄──────────────────────────────│
     │                               │
     │  POST localhost:3000/lab1/acs │
     │  SAMLResponse=<base64>        │
     │──────────────────────────────►│ vulnerable-saml-sp:3000
     │                               │  [fetches cert from saml-idp:8080]
     │                               │  [verifies signature]
     │                               │  [reads NameID ← VULN IS HERE]
     │  302 → /dashboard             │
     │◄──────────────────────────────│
     │                               │
     │  GET localhost:3000/dashboard │
     │──────────────────────────────►│
     │  [shows authenticated user]   │
     │◄──────────────────────────────│
```

Key insight: The SP fetches the IdP cert server-to-server (`saml-idp:8080` — internal Docker DNS), but redirects your **browser** to `localhost:8080` which Docker maps to the same container via the published port.
