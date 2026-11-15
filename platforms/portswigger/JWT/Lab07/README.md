# JWT Authentication Bypass via `kid` Header Path Traversal

## Vulnerability Overview

This lab demonstrates a JWT authentication bypass caused by a server that uses the `kid` (Key ID) header parameter to build a filesystem path, without validating or sanitizing it first.

Some JWT implementations store their verification keys as individual files on disk rather than in a database or hardcoded config. To decide which key file to load for a given token, the server takes the `kid` value straight out of the (attacker-controlled) JWT header and concatenates it onto a base directory path, roughly:

```
key = read_file(KEYS_DIRECTORY + kid)
```

Because `kid` is part of the token itself, the client — i.e. the attacker — controls its exact contents. If the server does naive string concatenation instead of validating `kid` against a strict allowlist of known key filenames, this is a textbook **path traversal** vulnerability: `../` sequences in `kid` can walk the path out of the intended keys directory and point the "key lookup" at an arbitrary file elsewhere on the filesystem.

The exploit angle is specific and clever: the goal isn't to *read* a file's contents back to the attacker (as in a typical path-traversal information-disclosure bug). The goal is to make the server load, as its HMAC verification secret, a file whose contents the attacker can predict in advance — ideally a file guaranteed to exist and be empty. `/dev/null` fits perfectly: reading it always returns zero bytes, on essentially any Unix-like system, without needing any special privileges.

If the attacker signs their own forged token using an **empty string** as the HS256 secret, and tricks the server into also reading an empty secret (by pointing `kid` at `/dev/null`), both sides land on the same "secret" — and the forged signature verifies successfully, even though the attacker never had access to the server's real signing key.

This is the third JWT lab in this series built around the same root cause — "a header parameter meant to help locate the right key becomes a vector for supplying an attacker-chosen key" — expressed three different ways:

| Lab | Header | Mechanism |
|---|---|---|
| `jwk` header injection | `jwk` | Key is embedded directly in the token |
| `jku` header injection | `jku` | Key is fetched from an attacker-hosted URL |
| **`kid` path traversal** (this lab) | `kid` | Key is read from an attacker-chosen file path on the server's own disk |

## Objective

Forge a JWT that the server accepts as belonging to the `administrator` user, by setting the `kid` header to a path-traversal sequence pointing at a predictable, empty file (`/dev/null`), then signing the token with an empty-string HS256 secret — so the attacker's signature and the server's "retrieved key" match. Use the resulting access to the admin panel to delete the user `carlos`.

## Tools Used

- Burp Suite (Repeater, JWT Editor extension)

## Related Labs

| Lab | Core Flaw |
|---|---|
| JWT authentication bypass via flawed signature verification | Server accepts `alg: none`, skipping verification entirely |
| JWT authentication bypass via weak signing key | HS256 secret is weak/guessable and crackable offline |
| JWT authentication bypass via `jwk` header injection | Server trusts a public key embedded directly in the token header |
| JWT authentication bypass via `jku` header injection | Server trusts a public key fetched from an attacker-hosted URL |
| **JWT authentication bypass via `kid` header path traversal** | Server trusts a key file read from an attacker-controlled filesystem path |
| JWT authentication bypass via algorithm confusion | Server reuses its RSA public key as an HS256 secret when `alg` is switched |
