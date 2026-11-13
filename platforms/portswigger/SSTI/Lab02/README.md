# Basic SSRF Against Another Back-End System

**Source:** PortSwigger Web Security Academy
**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** Apprentice

## Overview

This lab contains a stock-check feature that makes a server-side HTTP request to an internal API, in the same way as the basic localhost SSRF lab. The difference here is that the internal admin interface is **not** on the same host as the main application — it lives on a separate machine somewhere inside the `192.168.0.0/24` private network, listening on a non-standard port (`8080`).

Because the exact internal IP is unknown, this lab requires an additional step beyond the basic case: **network discovery**. The vulnerable application server is a legitimate member of that internal network and can reach any address within it, but the attacker has no visibility into which address actually hosts the admin service. The attacker must use the SSRF itself as a scanning primitive — sending one probe per candidate IP and observing which response differs from the rest.

## Vulnerability

- **Type:** SSRF (unvalidated URL parameter fetched server-side)
- **Root cause:** The stock-check parameter accepts an arbitrary URL with no validation on host or port, and the backend performs the fetch unconditionally.
- **Trust boundary violated:** Network-location-based trust — any request originating from inside the private network is treated as implicitly trusted by the internal admin service, with no real authentication.

## Impact

Beyond reaching a single known internal endpoint, this variant demonstrates that SSRF can be used to:
- **Enumerate internal network topology** — discover which hosts exist and which services they run, purely through response differences (status, size, timing), without ever directly contacting those hosts
- Reach and interact with internal services that have no intention of being externally discoverable, let alone externally reachable
- Chain discovery → exploitation in a single vulnerable parameter

## Objective

1. Use the stock-check SSRF to scan the `192.168.0.1`–`192.168.0.255` range on port `8080` for a live admin interface
2. Identify the host and confirm the admin panel
3. Use it to delete the user `carlos`

## Tools used

Solved without Burp Suite, using:
- Chrome DevTools (Network tab) — to capture the original request/response and parameter names
- `ffuf` — to fuzz the internal IP octet and isolate the one host that responds differently from the rest
- `curl` — to confirm the finding, extract the delete-user link, and trigger the final action

See `INDEX.md` for the full walkthrough.
