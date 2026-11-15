# JWT Authentication Bypass via jwk Header Injection

**Source:** PortSwigger Web Security Academy
**Category:** JSON Web Token (JWT) Authentication Bypass
**Difficulty:** Practitioner

## Overview

This lab's server supports the `jwk` (JSON Web Key) header parameter — a legitimate JWT feature that allows a token to carry its own verification key directly, inline in the header, rather than relying on a key the verifier already possesses. The server's flaw is that it never checks whether the embedded key actually came from a trusted source before using it to verify the token's signature.

Since `n`/`e` (the RSA public key fields in a `jwk` object) are just data the token supplies about itself, an attacker can generate an entirely new, self-controlled RSA key pair, embed the public half in the header, sign the token with the matching private half, and have the server dutifully verify the signature against a key it was never supposed to trust in the first place.

## Vulnerability

- **Type:** Authentication bypass via unauthenticated key injection in the `jwk` header parameter
- **Root cause:** The server extracts and trusts whatever public key is embedded in a token's `jwk` header field, instead of verifying exclusively against its own pre-known, pre-trusted key(s).
- **Why this defeats RSA signing's purpose:** RSA/RS256 security relies on the verifier checking a signature against a key it already trusts (its own public key, tied to a private key only the legitimate server holds). If the verifier instead uses whatever key the *token itself* supplies, the attacker simply supplies their own — a signature check that always passes, because the attacker controls both halves of the key pair being checked.

## Impact

Full authentication bypass: an attacker can forge arbitrarily-claimed, validly-signed tokens for any identity (including an administrator) without ever needing access to the server's actual signing key.

## Objective

1. Confirm `/admin` is restricted to the `administrator` identity
2. Generate a new RSA key pair
3. Forge a token claiming `sub: administrator`, embed the new key pair's public half via the `jwk` header, and sign with the private half
4. Access `/admin` and delete the user `carlos`

## Tools used

- Burp Suite + **JWT Editor** extension (BApp Store) — generates the RSA key pair and automates the entire embedded-JWK attack (header construction, signing) in one step via its built-in "Attack → Embedded JWK" feature
- Burp Repeater — used end-to-end for capturing, editing, and resending the request, keeping the whole workflow in one tab rather than bouncing between tools

See `INDEX.md` for the full walkthrough.
