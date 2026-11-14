# JWT Authentication Bypass via Flawed Signature Verification

**Source:** PortSwigger Web Security Academy
**Category:** JSON Web Token (JWT) Authentication Bypass
**Difficulty:** Apprentice

## Overview

This lab uses JWTs to manage session state. The server is misconfigured to accept tokens with the algorithm header `alg: none` — a legitimate JWT spec value meaning "this token is intentionally unsigned" — without actually enforcing that such tokens originate from a trusted, internal source. An attacker can construct their own token from scratch, declare `alg: none`, and have the server trust whatever claims they put in the payload with zero cryptographic verification.

## Vulnerability

- **Type:** Authentication/authorization bypass via improper JWT signature verification
- **Root cause:** The server's JWT verification logic honors the `none` algorithm unconditionally on tokens from untrusted clients, rather than rejecting it outright or restricting it to internal use only.
- **Why this defeats the purpose of signing:** A JWT signature exists so the server can confirm *it* (or a trusted party holding the secret) issued the claims inside — preventing a client from just inventing its own privilege level. Honoring `alg: none` on an external-facing token removes that guarantee entirely: the client gets to assert anything it wants.

## Impact

Complete authentication/authorization bypass — any user can forge a token claiming to be any other user, including an administrator, without needing any credentials, secret key, or cryptographic material whatsoever.

## Objective

1. Log in as `wiener:peter` and capture the session JWT
2. Modify the token's header to declare `alg: none` and the payload to claim the `administrator` identity
3. Strip the signature entirely (while preserving the token's three-segment structure)
4. Use the forged token to access `/admin` and delete the user `carlos`

## Tools used

- Burp Suite's **JWT Editor** extension — to decode, edit, and reconstruct the token's header/payload, including a built-in "Attack → None" feature that automates stripping the signature and trying case variants of `none`
- Browser DevTools — to capture the original session cookie

See `INDEX.md` for the full walkthrough.
