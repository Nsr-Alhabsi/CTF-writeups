# JWT Authentication Bypass via Weak Signing Key

**Source:** PortSwigger Web Security Academy
**Category:** JSON Web Token (JWT) Authentication Bypass
**Difficulty:** Practitioner

## Overview

This lab's server correctly verifies HS256 signatures — unlike the previous lab, there's no `alg: none` shortcut available. The vulnerability instead lies in the strength of the secret key itself: it's a common/guessable word rather than a long, random, high-entropy value. Because HMAC verification is just "recompute the hash with a candidate key and compare," an attacker holding a legitimate (unmodified) token can brute-force the secret entirely offline, using a wordlist of common JWT secrets, with no interaction with the server during the cracking phase itself.

## Vulnerability

- **Type:** Authentication bypass via weak/guessable HMAC signing secret
- **Root cause:** The server signs and verifies JWTs with HS256 using a secret key drawn from a small, guessable keyspace (e.g. a dictionary word) rather than a long, random value.
- **Why HS256 itself isn't the problem:** HMAC-SHA256 is cryptographically sound — the issue is entirely about key strength. A weak key makes any HMAC scheme brute-forceable regardless of how strong the underlying hash function is.

## Impact

Full authentication bypass: once the secret is recovered, an attacker can forge arbitrarily-claimed, *validly signed* tokens for any user, including an administrator — indistinguishable from a token the server itself issued.

## Objective

1. Log in as `wiener:peter` and capture a valid session JWT
2. Brute-force the signing secret offline, using a wordlist of common JWT secrets
3. Use the recovered secret to sign a modified token claiming the `administrator` identity
4. Access `/admin` and delete the user `carlos`

## Tools used

- `hashcat` (mode `16500`, JWT) with a CPU-based OpenCL runtime (`pocl`, since no GPU was available) — to brute-force the secret from a wordlist
- Burp Suite's **JWT Editor** extension — to edit the payload, create a symmetric signing key from the cracked secret, and produce a validly re-signed token

See `INDEX.md` for the full walkthrough.
