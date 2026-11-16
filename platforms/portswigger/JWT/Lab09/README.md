# JWT Authentication Bypass via Algorithm Confusion (No Exposed Key)

## Vulnerability Overview

This lab is a harder variant of the standard algorithm confusion attack. The underlying flaw is identical to the previous lab: the server signs tokens with **RS256** (asymmetric), but its JWT verification code also accepts **HS256** without pinning down which algorithm family is actually expected. If an attacker can get the server's RSA public key into the HS256 code path as if it were a symmetric secret, a forged `alg: HS256` token signed with those bytes will verify successfully.

The difference here: **the server never exposes its public key anywhere.** There's no `/jwks.json`, no `.well-known` endpoint, nothing to simply fetch. This removes the easy half of the previous attack — you now have to **derive** the public key yourself, using nothing but tokens the server has already legitimately signed.

### How the key is recovered without ever seeing it

This relies on a property of RSA signing itself. For any valid signature `s` over a message `m`, the relationship

```
s^e ≡ m (mod n)
```

always holds, where `n` is the RSA modulus (part of the public key) and `e` is the public exponent (almost always `65537`, i.e. `AQAB`). Rearranged, this means:

```
n divides (s^e - m)
```

If you collect **two separate valid signatures** from the same (unknown) private key — e.g. two different login sessions — you get two such expressions, both divisible by the same unknown `n`. Computing the **greatest common divisor (GCD)** of `(s1^e - m1)` and `(s2^e - m2)` recovers `n` (or a small multiple of it) — entirely from public information (the tokens themselves), without ever touching the server's actual key material.

This technique is implemented by a known, purpose-built tool: **`silentsignal/rsa_sign2n`** on GitHub, which PortSwigger also ships as a ready-to-run Docker image (`portswigger/sig2n`) specifically to avoid the dependency headaches of running a decade-old Python 2 script directly.

## Objective

Capture two valid session JWTs, use the GCD-based key-recovery technique to derive the server's RSA public key without it ever being exposed directly, then use that recovered key — converted into a usable HS256 secret — to forge a token with `alg: HS256` and `sub: administrator`. Use the resulting access to `/admin` to delete the user `carlos`.

## Tools Used

- Burp Suite (Repeater, JWT Editor extension)
- Docker (`portswigger/sig2n` image — a packaged build of the `rsa_sign2n` key-recovery tool)
- A terminal for base64url encoding

## Related Labs

| Lab | Core Flaw |
|---|---|
| JWT authentication bypass via flawed signature verification | Server accepts `alg: none`, skipping verification entirely |
| JWT authentication bypass via weak signing key | HS256 secret is weak/guessable and crackable offline |
| JWT authentication bypass via `jwk` header injection | Server trusts a public key embedded directly in the token header |
| JWT authentication bypass via `jku` header injection | Server trusts a public key fetched from an attacker-hosted URL |
| JWT authentication bypass via `kid` header path traversal | Server trusts a key file read from an attacker-controlled filesystem path |
| JWT authentication bypass via algorithm confusion | Server reuses its exposed RSA public key as an HS256 secret |
| **JWT authentication bypass via algorithm confusion (no exposed key)** | Server reuses its *unexposed* RSA public key as an HS256 secret, recovered via signature math alone |
