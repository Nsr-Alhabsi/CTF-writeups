# Walkthrough: SSRF with Whitelist-Based Input Filter

> Replace `<LAB-ID>` and `<SESSION>` with your own lab instance values throughout.

## 1. Confirm the filter does real host parsing

Test a direct disallowed host:
```bash
curl -i https://<LAB-ID>.web-security-academy.net/product/stock \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://127.0.0.1/admin'
```
Response:
```
"External stock check host must be stock.weliketoshop.net"
```
This specific, descriptive rejection message (compare to earlier labs' generic "blocked" message) tells you the filter genuinely extracts a hostname and compares it — not a naive substring check.

## 2. Rule out naive substring-matching bypasses first

Try embedding the allowed hostname as URL userinfo:
```
stockApi=http://stock.weliketoshop.net@localhost/admin
```
If this is **also rejected** with the same specific host-mismatch message, the filter correctly parses URL authority syntax and extracts `localhost` as the real host despite the decoy userinfo. This rules out the simplest bypass and confirms you're dealing with a filter that uses a real URL-parsing library.

> **curl gotcha:** `--data-urlencode 'value-with-no-name'` (missing the `stockApi=` prefix) causes curl to try to read a local file, because without a leading `=`, curl interprets the content as `name@filename` syntax. Always include the field name explicitly: `--data-urlencode 'stockApi=...'`.

## 3. Test for parser disagreement using embedded, encoded fragment syntax

The next-level technique targets a gap between the **validating** component and the **requesting** component's URL parsers, using the `#` (fragment) character, which is technically part of the authority-confusion vector:

1. Try appending a literal `#` to the userinfo — this gets rejected outright (the filter understands `#` well enough to reject it at face value).
2. **Double-URL-encode** the `#` (`#` → `%23` → `%2523`) and test again. A sudden, unusual error (e.g. an "Internal Server Error" referencing a nonsensical hostname like the literal word used as a test userinfo) is a strong signal: the validator decoded the value **once** (seeing `%23`, not yet a real `#`, so it passed the check), while the component that actually dispatches the request decoded it **again** (`%23` → `#`), at which point everything after `#` became a discarded URL fragment — changing what host the real request actually targets.

## 4. Construct the final payload

```
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/del
```

**How this resolves at each layer:**
- **Validator** (single decode): `%2523` → `%23`. Sees userinfo `localhost:80%23`, host `stock.weliketoshop.net` → matches allowlist → **approved**.
- **Real HTTP client** (decodes again during its own normalization): `%23` → `#`. The string is now effectively `http://localhost:80#@stock.weliketoshop.net/admin/del`. Everything from `#` onward is a **fragment**, discarded before the request is sent. The real connection target becomes `localhost:80`.

```bash
curl -i https://<LAB-ID>.web-security-academy.net/product/stock \
  -b 'session=<SESSION>' \
  --data-raw 'stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/del'
```

> **Critical:** send this with `--data-raw`, not `--data-urlencode`. The payload's `%2523` is an intentional, pre-crafted double-encoding — `--data-urlencode` would re-encode the existing `%` characters, corrupting it into a third layer of encoding and breaking the exploit.

## 5. Verify

If the delete action succeeds directly via this path (`/admin/del`), refresh the lab page — status should flip to **"Solved."**

---

## Key takeaways

- **A "proper" allowlist (real URL parsing, not substring matching) is necessary but not sufficient.** It still fails if the code that validates a URL and the code that acts on it don't share identical parsing behavior for ambiguous syntax.
- **Build confidence in a technique by first ruling out mechanical errors.** Before concluding a bypass concept is wrong, verify the raw bytes sent (`xxd`), check for curl encoding mistakes (`--data-urlencode` vs `--data-raw`), and compare the response against known baselines — a parsing-sounding error (missing parameter, invalid file, generic crash) usually means the request malfunctioned before reaching real filter logic, which is a different problem than "the filter caught my real payload."
- **Distinguishing "wrong technique" from "broken payload":** if a new input produces the *same generic rejection* as a deliberately bad control input, the filter is doing its job correctly and a different bypass concept is needed. If it produces a *new, unprecedented* error, that's usually a sign you've broken through to a different (often simpler) problem.
- **Unusual/verbose error messages are valuable, not just noise.** An "Internal Server Error" naming a nonsensical host it tried to connect to was the single clearest piece of evidence that two parsing layers disagreed — always read full error bodies, not just status codes.

## Related labs

| Lab | What's different |
|---|---|
| SSRF with blacklist-based input filter | Weaker defense — bypassed via simple representation tricks (`127.1`, percent-encoding) rather than parser-disagreement attacks |
| SSRF with filter bypass via open redirection | Allowlist bypassed by chaining in an unrelated open redirect, rather than exploiting URL parser ambiguity directly |
| Blind SSRF with Shellshock exploitation | Combines blind SSRF (OOB detection via Burp Collaborator) with a Shellshock RCE payload for command execution and data exfiltration |
