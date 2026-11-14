# Walkthrough: JWT Authentication Bypass via Weak Signing Key

## 1. Capture a valid session JWT

Log in as `wiener:peter`. Grab the session cookie (the JWT) from DevTools — Application → Cookies, or the `Set-Cookie` header.

## 2. Set up hashcat to crack the secret

**If hashcat reports "No devices found" (no GPU):** install a CPU-based OpenCL runtime so hashcat has something to run against.

```bash
# Arch / BlackArch
sudo pacman -S pocl

# Debian / Ubuntu / Kali
sudo apt install pocl-opencl-icd
```

Confirm a device is now detected:
```bash
hashcat -I
```

## 3. Save the JWT and get the wordlist

```bash
echo -n '<your full JWT, all three segments>' > jwt.txt
curl -o jwt.secrets.list https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list
```

## 4. Run the crack

```bash
hashcat -a 0 -m 16500 jwt.txt jwt.secrets.list
```
- `-a 0` — straight dictionary attack
- `-m 16500` — hash mode for JWT

This ran at ~177 kH/s and found a match within seconds against a ~104,000-entry wordlist. The output line is:
```
<full JWT>:secret1
```
Everything after the final `:` is the cracked secret — here, `secret1`.

> If hashcat reports "Exhausted" with no match, double-check the JWT file contains the complete, unmodified token with no trailing newline (`echo -n`, not `echo`) and nothing else in the file.

## 5. Edit the payload

In Burp's JWT Editor (or any JWT tool), change the identity claim:
```json
{"iss": "portswigger", "exp": <future-timestamp>, "sub": "administrator"}
```
Leave `alg: HS256` as-is this time — a weak-key attack produces a *genuinely valid* signature, unlike the previous lab's unsigned-token trick.

## 6. Create a symmetric signing key from the cracked secret

Re-signing requires the JWT Editor to have an actual key object to sign with — it won't let you just type a secret into the "Sign" dialog directly.

1. Go to the **Keys** tab in the extension
2. Create a **New Symmetric Key**
3. Set its key material (`k` value) to the cracked secret, `secret1` — if the input expects base64url rather than raw text, make sure the *decoded* value equals `secret1` exactly
4. Save the key

## 7. Sign the edited token

Back in the JWT tab, click **"Sign"**, select the symmetric key just created, and confirm. This produces a new, validly-signed HS256 token — the server's verification will succeed because the signature now genuinely matches, computed with the real secret.

## 8. Deploy and verify

Replace your session cookie with the newly signed token, navigate to `/admin`, delete `carlos`, and refresh the lab page to confirm **"Solved."**

---

## Key takeaways

- **A cryptographically strong algorithm doesn't protect a weak key.** HS256 itself has no flaw here — the entire vulnerability is keyspace size. This generalizes well beyond JWTs: any HMAC/password-hash scheme is only as strong as the actual entropy of its secret.
- **Possessing one valid, unmodified token is enough to crack the secret offline.** No repeated requests to the server are needed during the cracking phase — you're verifying guesses against math you can run locally, which is both fast and undetectable until you actually use the forged result.
- **Common/public JWT-secret wordlists exist and are frequently sufficient.** Developers reusing example secrets from tutorials, frameworks, or defaults is common enough that a wordlist like Wallarm's `jwt-secrets` list often succeeds against real misconfigured systems, not just lab environments.
- **Editing a claim ≠ forging a valid token.** Unlike the `alg: none` lab, here you must actually re-sign with the real key — editing the payload alone and leaving a stale signature will still fail verification, since HS256 is genuinely being checked.

## Related labs

| Lab | What's different |
|---|---|
| JWT authentication bypass via flawed signature verification | No cracking needed — the server accepts `alg: none` unconditionally, so the signature can simply be stripped rather than forged |
| JWT authentication bypass via jwk header injection | Exploits the `jwk` header parameter, letting an attacker supply their own key material that the server trusts without validating its origin |
| JWT authentication bypass via algorithm confusion | Exploits mismatched handling between asymmetric (RS256) and symmetric (HS256) verification paths |
