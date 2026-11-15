# JWT Authentication Bypass via Algorithm Confusion

## Vulnerability Overview

This lab demonstrates a JWT authentication bypass that exploits ambiguity in how a server's JWT verification library handles **multiple supported algorithm families**, rather than exploiting a flaw in any single algorithm.

The server signs tokens using **RS256** — an asymmetric algorithm. Like all RSA-based schemes, this means there are two distinct keys:

- a **private key**, known only to the server, used to *sign* tokens
- a **public key**, intentionally shared and non-secret, used to *verify* signatures

Because the public key is meant to be shared, it's often published at a standard, discoverable endpoint (typically `/jwks.json` or `/.well-known/jwks.json`) — exactly the kind of endpoint you'd expect a server to expose so that other services can verify its tokens.

The vulnerability arises when the server's JWT verification code accepts *more than one algorithm family* without the application explicitly restricting which one it expects — a common pattern in JWT libraries that expose a single generic `verify(token, key)` function covering both RSA (RS256) and HMAC (HS256) algorithms. Internally, this kind of code often looks conceptually like:

```
if alg == "RS256": verify_asymmetric(token, key)
if alg == "HS256": verify_hmac(token, key)
```

The critical flaw: `key` is the *same variable* in both branches — the RSA public key the server always uses for verification. That's correct behavior for RS256 (verifying with the public half is exactly right). But if an attacker submits a token claiming `alg: HS256`, the same public key bytes get fed into the HMAC branch instead — and HMAC doesn't interpret those bytes as "a public key," it just treats them as **raw secret material** to run through SHA-256.

Since the RSA public key is, by design, not secret, an attacker can retrieve it from the server's own published JWKS endpoint, then use those exact bytes as an HS256 signing secret to forge a token that the server's naive verification code will accept as genuinely signed.

## Why This Is Different From the Earlier JWT Labs

| Lab | What made the server trust a forged token |
|---|---|
| `alg: none` | Server skipped verification entirely |
| Weak HS256 secret | Secret was guessable/crackable offline |
| `jwk` header injection | Server trusted a key embedded in the token |
| `jku` header injection | Server trusted a key fetched from an attacker URL |
| `kid` path traversal | Server read a key from an attacker-chosen file path |
| **Algorithm confusion** (this lab) | Server reused one key across two *fundamentally different* cryptographic operations, depending on attacker-controlled `alg` |

This is the most structurally subtle of the JWT labs: nothing about the `kid`, `jwk`, or `jku` headers is involved at all. The entire exploit hinges on the fact that **knowing an algorithm's legitimate public value is not the same as that value being safe to use in a different algorithm's context.**

## Objective

Retrieve the server's RSA public key from its exposed JWKS endpoint, convert it into the exact byte representation the server's backend code holds internally (PEM format), use those bytes as an HS256 secret to sign a forged token with `sub: administrator`, and use the resulting admin access to delete the user `carlos`.

## Tools Used

- Burp Suite (Repeater, JWT Editor extension)
- A terminal for base64url encoding (or an equivalent key-conversion step)

## Related Labs

| Lab | Core Flaw |
|---|---|
| JWT authentication bypass via flawed signature verification | Server accepts `alg: none`, skipping verification entirely |
| JWT authentication bypass via weak signing key | HS256 secret is weak/guessable and crackable offline |
| JWT authentication bypass via `jwk` header injection | Server trusts a public key embedded directly in the token header |
| JWT authentication bypass via `jku` header injection | Server trusts a public key fetched from an attacker-hosted URL |
| JWT authentication bypass via `kid` header path traversal | Server trusts a key file read from an attacker-controlled filesystem path |
| **JWT authentication bypass via algorithm confusion** | Server reuses its RSA public key as an HS256 secret when `alg` is switched |
