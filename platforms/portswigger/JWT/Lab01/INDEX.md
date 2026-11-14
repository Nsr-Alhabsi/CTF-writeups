# Index — JWT Authentication Bypass via Unverified Signature

Quick navigation for `README.md`. Both the Burp Suite and curl walkthroughs live in that single file, side by side, so you can compare approaches without switching documents.

## Contents

- [Overview](README.md#overview) — what the vulnerability is and the lab's goal
- [Background: JWT structure](README.md#background-jwt-structure) — header / payload / signature refresher
- **Method 1: Burp Suite**
  - [Step 1 — Capture a valid session](README.md#step-1--capture-a-valid-session)
  - [Step 2 — Edit the JWT](README.md#step-2--edit-the-jwt)
  - [Step 3 — Target the privileged endpoint](README.md#step-3--target-the-privileged-endpoint)
  - [Step 4 — Perform the privileged action](README.md#step-4--perform-the-privileged-action)
- **Method 2: curl**
  - [Step 1 — Log in and capture a session cookie](README.md#step-1--log-in-and-capture-a-session-cookie)
  - [Step 2 — Decode the token](README.md#step-2--decode-the-token-to-see-its-structure)
  - [Step 3 — Build a forged payload](README.md#step-3--build-a-forged-payload)
  - [Step 4 — Reassemble the token](README.md#step-4--reassemble-the-token)
  - [Step 5 — Hit the privileged endpoint](README.md#step-5--hit-the-privileged-endpoint)
- [Optional: Python one-liner equivalent](README.md#optional-python-one-liner-equivalent)
- [Why this works](README.md#why-this-works)
- [Remediation](README.md#remediation-for-reference)

## At a glance

| Aspect | Detail |
|---|---|
| Vulnerability class | Broken authentication via JWT signature verification bypass |
| Root cause | Server calls a decode-only function instead of verify |
| Attack technique | Edit payload claims freely; keep the original (unchecked) signature |
| Tools covered | Burp Suite (Repeater + JWT tab), curl, optional Python (`pyjwt`) |
| Outcome | Forged admin identity grants access to a privileged action |

## How to use this folder

1. Start with `README.md` — pick whichever method (Burp or curl) matches your workflow; both reach the same result.
2. Swap in your own target host, credentials, and claim names — this writeup is intentionally generic, not tied to one specific lab instance.
3. See the **Remediation** section if you're documenting this for a fix recommendation rather than practicing the attack.
