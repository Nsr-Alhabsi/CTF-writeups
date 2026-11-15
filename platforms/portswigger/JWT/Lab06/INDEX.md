# Walkthrough: JWT Authentication Bypass via `kid` Header Path Traversal

## Setup

1. Install the **JWT Editor** extension from Burp's BApp Store, if not already installed.
2. Log in with the provided credentials (`wiener:peter`).
3. Capture an authenticated request (e.g. `GET /my-account`) and send it to Burp Repeater.
4. Change the path to `/admin` and send it. Confirm you're blocked — you're logged in as `wiener`, not `administrator`.
5. With the JWT Editor extension active, Burp exposes a **JSON Web Token** tab on this request (next to Pretty/Raw/Hex). Open it and inspect the current header — note the existing `kid` value, confirming the server tracks keys by some kind of identifier/filename.

## Building the Exploit

6. **Pick the target file.** The exploit needs a file on the server's filesystem whose exact contents are predictable — ideally zero-length. `/dev/null` fits: it's guaranteed to exist on virtually any Unix-like system and always reads as empty, with no special permissions required.

7. **Set the `kid` traversal path.** In the JWT header, set:
   ```json
   {
       "kid": "../../../../../../dev/null",
       "alg": "HS256"
   }
   ```
   The exact number of `../` segments needed depends on how deeply nested the server's real key-storage directory is — this isn't knowable in advance. Extra `../` beyond the filesystem root are harmless (going "up" from `/` just stays at `/`), so when in doubt, add a few extra rather than too few. If the traversal depth is wrong, expect an error distinct from a signature mismatch (e.g. a file-not-found-style response) — that's the signal to adjust the depth, not the secret.

8. **Create the matching symmetric key in Burp.**
   - Go to the JWT Editor **Keys** tab → **New Symmetric Key**.
   - Click **Generate** to produce a placeholder key object (any size is fine — it just needs to exist as a valid key entry).
   - Edit the key's `k` value and clear it to **empty**, so the key represents a zero-byte secret — matching what the server will read from `/dev/null`.

9. **Edit the payload.** Change the `sub` claim from `wiener` to `administrator`. (This step is easy to skip in the rush of getting the traversal and signature right — double check it before sending, since a technically-valid-but-unprivileged token won't get you anywhere.)

10. **Sign the token.** Click **Sign**, select your empty-secret symmetric key, and make sure **"Don't modify header"** is checked — this preserves your manually-set `kid` traversal string and `alg` value instead of letting the extension overwrite them with defaults.

11. **Send the request** to `/admin`. If the traversal depth and empty-secret encoding are both correct, the server reads `/dev/null` as "the key for this `kid`," finds it matches the empty string you signed with, and accepts the forged token as valid — granting admin access.

12. In the admin panel response, locate the delete link for `carlos`: `/admin/delete?username=carlos`. Send this request to complete the lab.

## Key Takeaways

- **The exploit never needed to "break" HMAC.** HS256 verification worked exactly as designed — the flaw is entirely in *what the server uses as the key*, not in the cryptographic algorithm. Once the attacker and the server are using the same (empty) secret, the signature is completely legitimate from a purely cryptographic standpoint.
- **Path traversal isn't only about reading sensitive files.** The classic mental model ("use `../` to read `/etc/passwd`") is only half the story. Here, the traversal's value comes from forcing the server to use a *predictable* file as cryptographic material — the attacker doesn't care what's "secret" about `/dev/null`; they care that its contents are known and controllable from the outside.
- **Any header value that gets used to construct a filesystem path, URL, or other resource locator is attacker input and needs strict validation** — ideally a fixed allowlist of acceptable values (e.g. "the key ID must be one of these three known names"), never free-form concatenation into a path.
- **"Don't modify header" is now a recurring must-check setting** across all three key-based JWT attacks (`jwk`, `jku`, `kid`) — Burp's default Sign behavior tends to normalize header values like `kid` back to the selected key's own stored metadata, which would silently undo your crafted payload if left unchecked.
- **This generalizes well beyond JWTs.** Any system that takes client-supplied input and uses it to pick a resource — a filename, a template, a config entry, a key — by naive path concatenation is vulnerable to the same class of bug, regardless of whether JWTs are involved at all.
