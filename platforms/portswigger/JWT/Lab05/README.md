# JWT Authentication Bypass via `jku` Header Injection

## Vulnerability Overview

This lab demonstrates a JSON Web Token (JWT) authentication bypass caused by a server that trusts the `jku` (JWK Set URL) header parameter without validating where it points.

JWTs can carry metadata in their header that tells the verifying server *how* to check the signature. Two relevant parameters:

- `kid` (Key ID) — tells the server which key, from its trusted set, to use for verification.
- `jku` (JWK Set URL) — tells the server *where to fetch* a JSON Web Key Set (a JWKS document) containing the public key(s) to use.

The `jku` parameter exists for legitimate use cases (e.g. key rotation, federated identity systems with multiple signing authorities). The vulnerability isn't the parameter itself — it's that some server implementations will fetch *any* URL placed in `jku` and blindly trust whatever public key they find there, instead of restricting lookups to a fixed, pre-approved list of trusted JWKS endpoints.

Because a JWT's signature is only meaningful if it's checked against a key the server actually trusts, this is a critical flaw: if an attacker can point `jku` at infrastructure they control, they can supply their own key, sign a forged token with the matching private key, and have the server "successfully" verify a token that was never issued by the real authentication system.

This is fundamentally different from the earlier JWT labs:
- **`alg: none`** exploited servers that skipped verification entirely.
- **Weak HS256 secret** exploited a server using a guessable *shared* secret (symmetric key).
- **`jwk` header injection** exploited a server trusting a public key embedded directly *inside* the token itself.
- **`jku` header injection** (this lab) exploits a server trusting a public key fetched from an *attacker-supplied external URL*.

In all RSA-based cases (`jwk` and `jku`), the exploit is possible because RSA is asymmetric — a public key can be freely shared and still be mathematically useless for forging signatures without its private counterpart, which only the attacker holds. The flaw is never "RSA is broken"; it's "the server never checked whether this public key came from somewhere it should trust."

## Objective

Forge a JWT that the server will accept as belonging to the `administrator` user, by hosting a malicious JSON Web Key Set (JWKS) on infrastructure the attacker controls, pointing the forged token's `jku` header at it, and signing the token with the matching private key — thereby gaining access to the admin panel and deleting the user `carlos`.

## Tools Used

- Burp Suite (Repeater, JWT Editor extension)
- PortSwigger's Exploit Server (a free, built-in hosting feature for crafting attacker-controlled responses — distinct from the paid Burp Collaborator)

## Related Labs

| Lab | Core Flaw |
|---|---|
| JWT authentication bypass via flawed signature verification | Server accepts `alg: none`, skipping verification entirely |
| JWT authentication bypass via weak signing key | HS256 secret is weak/guessable and crackable offline |
| JWT authentication bypass via `jwk` header injection | Server trusts a public key embedded directly in the token header |
| **JWT authentication bypass via `jku` header injection** | Server trusts a public key fetched from an attacker-hosted URL |
