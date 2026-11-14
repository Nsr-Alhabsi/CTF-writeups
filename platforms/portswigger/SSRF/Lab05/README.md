# SSRF with Filter Bypass via Open Redirection Vulnerability

**Source:** PortSwigger Web Security Academy
**Category:** Server-Side Request Forgery (SSRF) + Open Redirect
**Difficulty:** Practitioner

## Overview

This lab combines two separate vulnerabilities. The stock-check feature's SSRF is protected by an **allowlist**, not a blacklist — it only accepts `stockApi` values that are valid local paths on the application itself, rejecting any value that points directly at an external host or IP. On its own, this is a much stronger defense than the blacklists seen in earlier labs, since it doesn't matter how the forbidden destination is encoded or represented — the host is simply never on the allowed list.

However, the application separately contains an **open redirect**: an endpoint that accepts a user-controlled destination and issues an HTTP redirect to it, with no validation that the destination stays within the application's own domain. Chaining the two together defeats the allowlist entirely — the attacker supplies a local, allowed path (the redirect endpoint) as `stockApi`, and lets the application's own redirect respond with a `302` to the real, disallowed target. The filter only ever inspects the URL submitted, not the one ultimately fetched after following a redirect.

## Vulnerability

- **Type:** SSRF (allowlist-based host filter) chained with an unrelated open redirect
- **Root cause 1 (SSRF):** The host-matching allowlist correctly rejects direct requests to disallowed hosts, but does not re-validate the destination after the backend follows a redirect.
- **Root cause 2 (open redirect):** A feature that redirects based on a user-supplied parameter (here, a "next product" navigation link) does not restrict the destination to the application's own domain.
- **Why the combination matters:** Neither bug alone is sufficient for full exploitation in this scenario — the allowlist blocks direct SSRF, and the open redirect alone is merely a phishing/trust concern. Together, they bypass a defense that would otherwise have been robust.

## Impact

- Demonstrates that **allowlist-based SSRF defenses, while stronger than blacklists, are still incomplete if redirects aren't re-validated** at the final destination.
- Shows how a seemingly low-severity open redirect can escalate significantly in combination with another vulnerability — a common pattern in real-world bug bounty chains.

## Objective

1. Confirm the stock-check filter only accepts local, same-application paths in `stockApi`
2. Find an open redirect elsewhere on the site
3. Chain the two together to reach `http://192.168.0.12:8080/admin`
4. Delete the user `carlos` via the admin interface

## Tools used

- Chrome DevTools (Network tab) — to find candidate redirect endpoints and inspect `Location` headers
- `curl` — to test filter behavior, confirm the open redirect, and deliver the final chained payload

See `INDEX.md` for the full walkthrough.
