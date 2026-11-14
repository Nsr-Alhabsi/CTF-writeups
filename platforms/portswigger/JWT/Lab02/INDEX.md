# Walkthrough: JWT Authentication Bypass via Flawed Signature Verification

## 1. Understand JWT structure first

A JWT is three base64url-encoded segments separated by dots:
```
header.payload.signature
```
- **Header** — declares metadata, most importantly `alg` (the signing algorithm)
- **Payload** — the actual claims (e.g. `sub`, `role`, expiration)
- **Signature** — cryptographic proof the header+payload weren't tampered with, computed using a server-side secret/key

## 2. Log in and capture your JWT

Log in as `wiener:peter`. Grab the session cookie — it's the JWT — from DevTools (Application → Cookies, or the `Set-Cookie` header in Network tab).

## 3. Decode it to see the real claim structure

Using a JWT-aware tool (Burp's **JWT Editor** extension, or `jwt.io`, or manual base64url decoding) — don't guess field names:
```json
// Header
{"kid": "<some-uuid>", "alg": "HS256"}

// Payload
{"iss": "portswigger", "exp": 1794651634, "sub": "wiener"}
```
The identifying claim here is `sub`.

## 4. Edit the header and payload

- Header: change `"alg": "HS256"` → `"alg": "none"`
- Payload: change `"sub": "wiener"` → `"sub": "administrator"`

> **Note on the `kid` field:** leaving it in the header generally doesn't matter for a pure `none`-algorithm attack (there's no key lookup happening), but if a forged token is unexpectedly rejected, stripping the header down to just `{"alg":"none"}` is a reasonable thing to try.

## 5. Strip the signature — but keep the structure intact

This is the step that actually matters and is easy to get subtly wrong.

**Delete only the signature bytes, not the dot before them:**
```
# Correct — three segments, last one empty:
<header>.<payload>.

# Wrong — only two segments, parser may reject as malformed before even checking alg:
<header>.<payload>
```

**Also make sure no stale signature bytes remain.** If you only change the header/payload but leave the *original* signature attached, many JWT libraries will reject the token outright — either because they explicitly require an empty signature when `alg: none` is declared, or because the leftover signature (computed for completely different content) reads as corrupted/tampered data rather than "intentionally absent."

In Burp's JWT Editor, the **"Attack" → "None"** option automates this entire step: it strips the signature correctly and tries several capitalization variants of `none` (`none`, `None`, `NONE`) in case the server's check is case-sensitive.

## 6. Deploy the forged token

Replace your session cookie with the forged token (three segments, header declares `alg: none`, payload claims `administrator`, signature segment empty) and navigate to `/admin`.

## 7. Verify and complete the objective

Confirm you have admin access, then use the interface to delete the user `carlos`. Refresh the lab page — status should flip to **"Solved."**

---

## Key takeaways

- **`alg: none` is a legitimate part of the JWT spec, which is exactly what makes it dangerous.** It's meant for narrow, trusted-internal use cases. A server that honors it unconditionally on externally-supplied tokens has no real authentication left — the client can simply declare "don't check my signature" and be believed.
- **A token must be internally consistent with what it claims about itself.** `alg: none` is a promise of "no signature here" — a token that breaks that promise by still carrying old/leftover signature bytes gives verifying code a legitimate reason to reject it, even on a vulnerable server. Delete the signature cleanly, not partially.
- **Three-segment structure is non-negotiable even when a segment is empty.** The trailing dot after the payload isn't decorative — removing it changes the token from "three parts, one empty" to "two parts," which most parsers will flag as structurally invalid before `alg` is ever inspected.
- **Case sensitivity is worth testing when a straightforward bypass fails.** Some vulnerable libraries only match `none` exactly; others also accept `None`/`NONE`. This is the same "representation variant" mindset used throughout the earlier SSRF filter-bypass labs.

## Related labs

| Lab | What's different |
|---|---|
| JWT authentication bypass via weak signing key | Server properly verifies an HS256 signature, but the secret key is weak enough to brute-force offline with a wordlist, then used to forge validly-signed tokens |
| JWT authentication bypass via jwk header injection | Exploits the `jwk`/`jku`/`x5u` header parameters, which let an attacker supply their own key material that the server trusts |
| JWT authentication bypass via algorithm confusion | Exploits mismatched handling between asymmetric (RS256) and symmetric (HS256) verification, tricking the server into verifying a token against its own public key as if it were an HMAC secret |
