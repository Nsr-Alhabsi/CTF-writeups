# SSRF with Blacklist-Based Input Filter

**Source:** PortSwigger Web Security Academy
**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** Practitioner

## Overview

This lab builds on the basic localhost-SSRF scenario by adding **two weak anti-SSRF defenses** on top of the vulnerable stock-check feature. Both defenses are blacklist-based — they pattern-match against specific strings rather than validating the request's actual, final destination — which makes them bypassable once each one's exact matching logic is understood.

## Vulnerability

- **Type:** SSRF (unvalidated URL parameter fetched server-side), protected by two insufficient blacklist filters
- **Defense 1 — host filter:** Blocks literal strings associated with the loopback address (e.g. `localhost`, `127.0.0.1`), but does not account for alternate, equally valid representations of the same address.
- **Defense 2 — path filter:** Blocks the literal substring `admin` in the request path, but performs this check on an already-decoded value, allowing values that decode to `admin` only after passing through the check once more.
- **Root cause common to both:** Blacklisting checks for surface representations of a forbidden value rather than validating the fully-resolved/fully-decoded destination. Any filter implemented this way has gaps equal to the number of representations its author didn't think of.

## Impact

Same as the basic SSRF case — reaching the internal admin interface and acting on it — but this lab demonstrates that **adding a naive filter is not equivalent to fixing the vulnerability**. A blacklist narrows the attack surface slightly; it does not close it.

## Objective

1. Bypass the host-based blacklist to reach the loopback address
2. Bypass the path-based blacklist to reach the `/admin` route specifically
3. Use the admin interface to delete the user `carlos`

## Tools used

Solved entirely from the terminal:
- Chrome DevTools (Network tab) — to capture the original request and parameter structure
- `curl` — to iteratively test bypass payloads and read response differences
- `xxd` — to inspect raw outgoing bytes and rule out encoding mistakes on the client side

See `INDEX.md` for the full walkthrough and the reasoning behind each bypass.
