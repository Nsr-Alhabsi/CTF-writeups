# Walkthrough: JWT Authentication Bypass via Algorithm Confusion

## Setup

1. Log in with `wiener:peter`.
2. Capture an authenticated request (e.g. `GET /my-account`) and send it to Burp Repeater.
3. Change the path to `/admin` and send it — confirm you're blocked.

## Part 1 — Obtain the Server's Public Key

4. Request the server's published JWKS endpoint:
   ```
   GET /jwks.json HTTP/1.1
   Host: <lab-host>
   ```
   (If this 404s, try `/.well-known/jwks.json` as a fallback — this is the standard convention for where servers publish public signing keys.)
5. The response is a JWKS document structured like:
   ```json
   {
       "keys": [
           {
               "kty": "RSA",
               "e": "AQAB",
               "kid": "...",
               "n": "...",
               "alg": "RS256",
               "use": "sig"
           }
       ]
   }
   ```
6. If multiple keys are listed, match the `kid` against the `kid` in your current session JWT's header to confirm which entry is the one actually verifying your tokens.

## Part 2 — Convert the Public Key into Usable HS256 Secret Bytes

This is the step that actually makes the attack work, and it's the one most people get wrong mechanically. The server's backend code almost certainly holds its public key internally as a **PEM-formatted string** — not as raw `n`/`e` values. When its naive verification function treats that PEM string as an HMAC secret, you need to sign using the *exact same bytes* to produce a matching signature.

7. In Burp's JWT Editor **Keys** tab, click **New RSA Key**. Instead of generating a fresh key, load the server's real key — paste in the `n` and `e` values (or the full JWK object) from the JWKS response you fetched in step 5. Save it.
8. Right-click this saved key entry and select **Copy Public Key as PEM**. This gives you the exact PEM-formatted text block (`-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----`, including its line breaks) matching what the server's own code likely holds in memory.
9. Base64url-encode that **entire PEM string**, exactly as copied — headers, footers, and newlines included, without trimming anything:
   ```bash
   cat pubkey.pem | base64 -w0 | tr '+/' '-_' | tr -d '='
   ```
10. In the JWT Editor **Keys** tab, click **New Symmetric Key** → **Generate** (to get a valid key skeleton), then replace its `k` value with the base64url string produced in step 9. Save.

## Part 3 — Forge and Sign the Token

11. Go back to your `/admin` request in Repeater and open the JSON Web Token tab.
12. In the **header**, change `alg` from `RS256` to `HS256`. (`kid` can be left as-is — this attack doesn't depend on key lookup by ID; it exploits key *reuse*, not key *selection*.)
13. In the **payload**, change `sub` to `administrator`.
14. Click **Sign**, and select the symmetric key you created in step 10 (the one holding the base64url-encoded PEM).
15. Send the request to `/admin`. If the PEM bytes you encoded match exactly what the server's code has loaded, the signature verifies and you gain admin access.
16. Find and send the link for deleting `carlos`: `/admin/delete?username=carlos`.

## Key Takeaways

- **The attack never breaks RSA or HMAC individually.** Both algorithms work exactly as designed. The flaw is purely architectural: the server's code lets a single value serve two mutually incompatible cryptographic roles (asymmetric public key vs. symmetric shared secret) depending on attacker-controlled input (`alg`).
- **A public key being non-secret is the whole point of asymmetric cryptography — until it gets reused somewhere that assumes secrecy.** The server publishing its RSA public key is completely correct behavior on its own; the bug only exists because that same value can also be coerced into acting as an HMAC key.
- **Exact byte representation matters enormously here.** Unlike other JWT labs where "close enough" values sometimes still work, this attack requires the *precise* bytes the server's code is holding — which is almost always the PEM string, not the raw JWK's `n`/`e` fields. Getting the PEM formatting (headers, footers, newline style) even slightly wrong produces a mismatched HMAC and a failed forgery that looks identical to "wrong approach" even when the overall technique is correct.
- **The real-world fix** is for JWT libraries/applications to pin and enforce a single expected algorithm (or a small explicit allowlist) at verification time, and never let the token's own `alg` header dictate which cryptographic code path runs.
- **CTF relevance:** this is one of the highest-value JWT techniques to have memorized cold, since "is the public key reused as an HMAC secret" is a near-automatic first check whenever a CTF challenge exposes any kind of public/JWKS endpoint alongside JWT-based auth.
