# Walkthrough: JWT Authentication Bypass via jwk Header Injection

## 1. Install the JWT Editor extension

In Burp, go to the **BApp Store** tab and install **JWT Editor**. This adds a dedicated "JSON Web Token" tab to Repeater/Proxy whenever a JWT is detected in a request, plus a **Keys** tab for managing key material.

## 2. Capture the admin-check request

1. Log in to your own account (`wiener:peter`)
2. Send the post-login `GET /my-account` request to **Repeater**
3. In Repeater, change the path to `/admin` and send it
4. Confirm the response shows admin access is restricted to the `administrator` user — this is your baseline target request to modify and resend

## 3. Generate a new RSA key pair

1. Go to the **JWT Editor Keys** tab (in Burp's main tab bar)
2. Click **New RSA Key**
3. Click **Generate** to create a fresh key pair automatically, then **OK** to save it

> You don't need to manually pick a key size — it's automatically sized to match what the attack needs later. You also never need to construct the key's `n`/`e` values yourself; the tool generates the full mathematically-linked pair (private and public) as one unit. A random or mismatched `n` value is useless here — it must come paired with a private key you actually hold, since you need to genuinely sign the forged token with it.

## 4. Edit the payload and run the attack

1. Back in Repeater, on your `GET /admin` request, switch to the extension's **JSON Web Token** tab
2. In the payload, change the `sub` claim to `administrator`
3. Click **Attack** (bottom of the tab) → select **Embedded JWK**
4. When prompted, select the RSA key generated in step 3, then click **OK**

This single action:
- Embeds the key pair's **public** half (`n`, `e`) into the JWT header as a `jwk` object
- Signs the modified token using the key pair's **private** half
- Updates the request body/cookie with the newly forged, validly-self-signed token

5. Confirm in the header view that a `jwk` parameter now appears, containing your public key

## 5. Send and verify

Send the request. The response should now show the actual admin panel instead of the access-denied page — the server verified your signature against the public key *you* supplied in the header, which of course matches, since you hold the corresponding private key.

## 6. Delete the target user

In the admin panel response, find the delete-user link:
```
/admin/delete?username=carlos
```
Send a request to this endpoint (via Repeater, same session token) to complete the objective. Refresh the lab page to confirm **"Solved."**

---

## Key takeaways

- **`jwk` is a legitimate, useful JWT feature — the vulnerability is entirely in misplaced trust, not the feature itself.** Embedding a verification key inline is fine when the verifier still independently confirms that key is one it should trust (e.g. checking it against a known allowlist of key IDs, or requiring it be signed by a separate, already-trusted certificate). Blindly trusting whatever key a token supplies defeats the entire point of signing.
- **RSA's asymmetry is what makes this specific attack possible.** You can freely generate new, valid key pairs because the public half is inherently meant to be shareable — there's no equivalent "generate your own secret and share half of it" move possible with a symmetric scheme like HS256 (that's why the weak-secret-cracking approach was needed for the HS256 lab instead).
- **Tooling matters for workflow efficiency, not just capability.** Doing the entire attack inside one Repeater tab (via the extension's dedicated JWT view) avoids manually round-tripping tokens between a browser's cookie editor and an external decoder — worth preferring over a more manual, multi-tool approach once a cleaner path is available.

## Related labs

| Lab | What's different |
|---|---|
| JWT authentication bypass via flawed signature verification | No key generation needed — the server accepts `alg: none` unconditionally, so the signature is simply stripped rather than forged |
| JWT authentication bypass via weak signing key | Server properly verifies HS256, but the secret is weak enough to brute-force offline and reuse for forging |
| JWT authentication bypass via algorithm confusion | Exploits mismatched handling between RS256 (asymmetric) and HS256 (symmetric) verification paths, tricking the server into treating its own public key as an HMAC secret |
