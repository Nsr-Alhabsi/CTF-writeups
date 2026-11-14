# SSRF with Whitelist-Based Input Filter

**Source:** PortSwigger Web Security Academy
**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** Expert

## Overview

This lab protects its stock-check feature with an **allowlist** that properly parses the submitted URL and validates the extracted hostname against `stock.weliketoshop.net` — a materially stronger defense than the blacklists seen in earlier labs, since it doesn't matter how a forbidden host is encoded or represented; it simply isn't the allowed one.

Defeating a real allowlist requires a different class of attack entirely: rather than disguising a bad value, you need to construct a URL that **two different URL-parsing implementations disagree about** — one implementation (the filter's validator) concludes the host is the allowed one, while a different implementation (the HTTP client that actually dispatches the request) concludes the host is something else entirely.

## Vulnerability

- **Type:** SSRF protected by a properly-implemented host allowlist, defeated via URL parser inconsistency
- **Root cause:** The validating component and the requesting component parse the same URL string differently when unusual syntax (embedded credentials, encoded fragment markers) is present. A URL containing `user@host` syntax, plus a percent-encoded `#` character, can be parsed by one component as "host = the allowed domain, with odd-but-valid userinfo" and by another component — after an additional decode pass — as "host = something else, everything after `#` is a discarded fragment."
- **Why this defeats even a correct-looking allowlist:** The allowlist check itself is doing the "right" thing — parsing the URL and checking the host field, not just substring matching. The vulnerability isn't in the allowlist's logic; it's in the fact that two separate pieces of code (validate vs. execute) don't treat the same ambiguous input identically.

## Impact

Demonstrates that even a security control implemented "correctly" (full URL parsing, allowlist rather than blacklist) can still be bypassed if the validating code path and the executing code path are not provably using identical parsing semantics — a subtle, high-severity class of bug distinct from simple pattern-matching failures.

## Objective

1. Confirm the filter performs real host extraction (not naive substring matching)
2. Find a URL construction where the validator's parsed host differs from the real HTTP client's parsed host
3. Reach `http://localhost/admin`
4. Delete the user `carlos`

## Tools used

- Chrome DevTools / Burp Repeater — to observe how specific URL constructs are accepted or rejected, isolating what the filter actually checks
- `curl` with `--data-raw` — to send precisely-controlled payloads without `--data-urlencode` adding unwanted extra encoding layers
- `xxd` — to confirm exact outgoing bytes when encoding mistakes were suspected

See `INDEX.md` for the full walkthrough.
