# Walkthrough: JWT Authentication Bypass via `jku` Header Injection

## Setup

1. Install the **JWT Editor** extension from Burp's BApp Store (Extensions tab → BApp Store → search "JSON Web Tokens").
2. Log in to the lab with the provided low-privilege credentials.
3. Capture the post-login `GET /my-account` request and send it to Burp Repeater (right-click → Send to Repeater, or `Ctrl+R`).
4. In Repeater, change the path to `/admin` and send it. You should get a response showing the admin panel is restricted to the `administrator` user — this confirms the endpoint exists and is the target.

## Part 1 — Host a Malicious JWK Set

The idea here is to stand up your own "trusted key source" that the server will be tricked into fetching from.

5. Go to the **JWT Editor Keys** tab (added to Burp's main tab bar by the extension).
6. Click **New RSA Key**.
7. In the dialog, click **Generate** to auto-generate a fresh RSA key pair, then **OK** to save it. You don't need to manually pick a key size — it updates automatically.
8. Open the lab's **Exploit Server** (accessible via a link/button in the lab, separate from Burp itself — this is a PortSwigger-hosted scratch server you can serve arbitrary content from).
9. In the exploit server's **Body** section, start with an empty JWK Set skeleton:
   ```json
   {
       "keys": [

       ]
   }
   ```
10. Back in the JWT Editor Keys tab, right-click the key pair you generated → **Copy Public Key as JWK**. This copies only the *public* half (safe to expose) in the correct JWK JSON format.
11. Paste that JWK object inside the `keys` array on the exploit server, so it looks like:
    ```json
    {
        "keys": [
            {
                "kty": "RSA",
                "e": "AQAB",
                "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
                "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw..."
            }
        ]
    }
    ```
12. Click **Store** on the exploit server. Note the full URL it's hosted at (e.g. `https://exploit-xxxx.exploit-server.net/`).

At this point, there's a real URL on the internet that, if fetched, returns a JWKS document "vouching for" a public key whose private half only you hold.

## Part 2 — Modify and Sign the JWT

13. Go back to the `GET /admin` request in Repeater. With the JWT Editor extension installed, Burp automatically detects the JWT in the `session` cookie and exposes a **JSON Web Token** tab alongside Pretty/Raw/Hex.
14. In the token's **header**, replace the existing `kid` value with the `kid` of the key you generated and uploaded (copy it exactly — it must match character-for-character with what's in your hosted JWKS).
15. Add a new header parameter: `"jku": "https://exploit-xxxx.exploit-server.net/"` (the exact URL where you stored the JWKS in step 12).
16. In the **payload**, change the `sub` claim to `"administrator"`.
17. Click **Sign** at the bottom of the JWT Editor tab. Select the RSA key you generated earlier.
18. In the signing dialog, make sure **"Don't modify header"** is selected — this ensures the `kid` and `jku` values you just set by hand aren't overwritten by the extension's default signing behavior (which would otherwise reset `kid` to the key's stored value).
19. Click **OK**. The token is now signed with your private key, and its header correctly points to your hosted public key.
20. Send the request. The response should now show the admin panel.
21. In the admin panel response, find the link for deleting `carlos`: `/admin/delete?username=carlos`. Send this request (e.g. via Repeater, changing the path and method as needed) to complete the lab.

## Key Takeaways

- **`jku` is a pointer, not proof.** Including a `jku` header doesn't mean the server verifies that the URL is one it should trust — many implementations will fetch and use *whatever* JWKS is at that URL. The fix is for servers to maintain a strict allowlist of trusted `jku` hosts rather than accepting arbitrary URLs from the token itself.
- **`kid` has to match exactly between the token and the hosted JWKS**, or the server won't find the "correct" key when it fetches your `jku` URL. In Burp JWT Editor, clicking **Sign** resyncs the header's `kid` to the selected key's stored `kid` by default — this is why the **"Don't modify header"** option exists and matters: without it, manually-set header fields like a custom `kid` or `jku` would get silently overwritten during signing.
- **Public key sharing is safe — that's the entire point of asymmetric crypto.** Copying "Public Key as JWK" and hosting it openly does not expose anything useful to defenders; only the private key (kept in Burp's Keys tab, never uploaded anywhere) can produce valid signatures. This is what makes the attack work: the server has no way to tell "a public key I generated myself to fool you" apart from "a public key from a legitimate source" unless it restricts *where* it will look.
- **This generalizes directly to real-world CTF/pentest scenarios**: any time you control a reachable HTTP endpoint (a webhook catcher, a storage bucket, a throwaway VPS, or — as here — a vendor-provided exploit server) and a JWT-based auth system accepts a `jku`/`x5u`-style header pointing at arbitrary URLs, the same technique applies: host your own key material, point the header at it, sign, and submit.
- **Troubleshooting note:** an "expired" response from the server refers to the token's own `exp` claim being in the past — it does not mean you need to restart the whole exploit chain. Just get the current Unix time (`date +%s`), add a reasonable offset, update `exp` in the payload, and re-sign.
