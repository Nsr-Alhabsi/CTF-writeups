# Walkthrough: JWT Authentication Bypass via Algorithm Confusion (No Exposed Key)

## Setup

1. Log in with `wiener:peter`.
2. Capture an authenticated request (e.g. `GET /my-account`) and send it to Burp Repeater.
3. Change the path to `/admin` and send it — confirm you're blocked.

## Part 1 — Collect Two Valid Signed Tokens

4. Capture your current session JWT from Burp (the `session` cookie value).
5. Get a **second**, distinct valid JWT signed by the same server key — log out and back in, or otherwise trigger a re-issue, so the new token has at least a different `exp` claim (this is enough to make the signed message different between the two, which the recovery math needs).
6. You should now have two full JWT strings (header.payload.signature). Note: their `kid` header values may differ between the two tokens — this is expected here, since there's no real key-lookup mechanism in play; the server verifies every token against one single hardcoded RSA key regardless of `kid`.

## Part 2 — Recover the Public Key via Docker

7. Pull and run PortSwigger's prebuilt key-recovery tool:
   ```bash
   sudo docker run --rm portswigger/sig2n '<token_A>' '<token_B>'
   ```
   **Important gotcha:** do **not** add the `-it` (interactive terminal) flags here. Adding `-it` caused the container to run successfully (exit code 0) but swallow all of its actual output — the tool ran, but nothing printed. Dropping `-it` and running it as a plain non-interactive command lets the output reach the terminal correctly.
8. Also double-check the image name carefully: it's **`portswigger/sig2n`** (one "n"), not `sign2n` — easy typo to make since the underlying GitHub project is named `rsa_sign2n`.
9. And make sure both token strings are pasted in full — a single missing leading character (especially the first `e` every JWT starts with, from `{` encoding to `ey`) causes a `UnicodeDecodeError` deep inside the tool with a confusing error message.
10. With all three of the above correct, the tool should output one or more candidate RSA public keys (and/or directly attempt forgery, depending on the tool's exact behavior) derived purely from the GCD of the two signatures' underlying math — without the server ever having exposed its key anywhere.

## Part 3 — Forge and Sign the Token

11. Using the recovered public key, follow the same process as the previous (exposed-key) algorithm confusion lab:
    - Load the recovered key into Burp's JWT Editor Keys tab as an RSA key (paste in the derived `n`/`e` values).
    - Right-click → **Copy Public Key as PEM**.
    - Base64url-encode the full PEM text (headers, footers, and newlines included, exactly as copied):
      ```bash
      cat pubkey.pem | base64 -w0 | tr '+/' '-_' | tr -d '='
      ```
    - Create a **New Symmetric Key** in Burp, replacing its `k` value with that base64url string.
12. On your `/admin` request's JWT Editor tab:
    - Change `alg` in the header from `RS256` to `HS256`.
    - Change `sub` in the payload to `administrator`.
13. Click **Sign**, select the symmetric key holding the encoded PEM, and send the request to `/admin`.
14. Find and send the delete link for `carlos`: `/admin/delete?username=carlos`.

## Key Takeaways

- **Not exposing a public key endpoint is not, by itself, a meaningful defense against algorithm confusion.** The public key is mathematically recoverable from nothing more than two ordinary, legitimately-issued signed tokens — artifacts the server hands out to every logged-in user as a matter of course. "Security through non-disclosure" collapses the moment the underlying cryptographic relationship between signatures and the modulus is understood.
- **The GCD recovery technique is a known, tooled attack**, not something to re-derive from scratch under time pressure. Recognizing "two signatures from an unknown RSA key, want the modulus" as a pattern that maps directly to `rsa_sign2n`/`sig2n` is the actual CTF-relevant skill — the underlying number theory doesn't need to be re-implemented live.
- **Docker-packaged CTF tools sidestep real dependency pain.** The standalone `rsa_sign2n` Python script is old enough to hit multiple Python 2-vs-3 incompatibilities at once (print statements, the removed `long` type, the removed `xrange`, strict typing in three-argument `pow()`, and build failures for `gmpy2`/`pycrypto` against modern Python header layouts). When a maintained Docker image exists for a tool like this, it is almost always faster to use it directly than to patch a decade-old script into working on a current system — but double-check exact image names and flags (`-it` silently swallowing output here is a good example of a flag that "shouldn't" matter but did).
- **A missing or extra single character in a copy-pasted token is a disproportionately common source of cryptic errors** (`UnicodeDecodeError`, failed JSON parsing, etc.) in any JWT-tooling workflow — when a tool fails in a way that looks like "garbage input" rather than "wrong logic," re-verify the raw input strings character-for-character before assuming the tool or technique is broken.
- **This completes the full JWT attack-surface tour**: `alg: none`, weak symmetric secrets, `jwk`/`jku`/`kid` header-trust failures, and now both variants of algorithm confusion. Every one of these labs reduces to the same root lesson — a JWT's header is attacker-controlled metadata, and any server behavior that lets that metadata influence *which* trust decision gets made, rather than just *how* an already-fixed decision gets checked, is exploitable.
