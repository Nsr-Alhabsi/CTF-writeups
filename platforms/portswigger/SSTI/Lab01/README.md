# Basic SSRF Against the Local Server

**Source:** PortSwigger Web Security Academy
**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** Apprentice

## Overview

This lab contains a stock-check feature on product pages that makes a server-side HTTP request to an internal stock API. The endpoint that performs this fetch accepts a fully attacker-controlled URL (`stockApi`) with no validation on the destination host.

Because the fetch happens **server-side**, requests appear to originate from `localhost` — which is implicitly trusted by the application's admin interface. This lets an external, unauthenticated attacker use the vulnerable server as a proxy to reach `/admin`, an endpoint normally unreachable from outside the network.

## Vulnerability

- **Type:** SSRF (unvalidated URL parameter fetched server-side)
- **Root cause:** The `stockApi` parameter is treated as a trusted internal value by the frontend, but the backend blindly performs an HTTP request to whatever URL is supplied — with no allow-list, no scheme restriction, and no distinction between internal and external hosts.
- **Trust boundary violated:** Network-location-based trust (`localhost` = trusted) instead of real authentication/authorization on the admin endpoint.

## Impact

An attacker can:
- Reach internal-only services and admin panels not exposed externally
- Perform actions on behalf of the server's trusted local identity (e.g. delete a user via the admin panel)
- Use the same technique more broadly for internal network/port scanning or cloud metadata exfiltration in real-world environments

## Objective

Use the SSRF to:
1. Reach the internal admin interface at `http://localhost/admin`
2. Delete the user `carlos`

## Tools used

Solved entirely from the terminal — no Burp Suite:
- Chrome DevTools (Network tab) — to capture the original request/response
- `curl` — to replay and modify the request
- `grep` — to extract the delete-link from the returned admin HTML

See `INDEX.md` for the full walkthrough.
