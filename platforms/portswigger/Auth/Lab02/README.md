# 2FA Simple Bypass

**Category:** Authentication — Multi-Factor
**Difficulty:** Apprentice
**CWE:** CWE-287 (Improper Authentication) / CWE-305 (Authentication Bypass by Primary Weakness)

## Vulnerability Overview

A two-stage login (password, then a 2FA/MFA code) is only as strong as the
*server-side* checks on the protected pages it's meant to gate. This lab's login flow
looks correct at the UI level — successfully submitting a username/password redirects
the browser to a "enter your verification code" page — but that redirect is just a
*suggestion*. The server never actually re-verifies, on a request to the protected
account page, whether the current session completed the second factor.

In other words: once the password check succeeds, the server issues a session that is
*already* fully trusted by `/my-account`. The 2FA step exists only as a navigational
nudge (the login page sends you there next), not as an enforced gate. An attacker who
knows this doesn't need to know, intercept, or brute-force the 2FA code at all — they
just skip the step the UI assumes they'll take, and request the protected resource
directly.

## Why This Matters

Two-factor authentication is only a meaningful control if *every* code path to a
protected resource actually checks that the second factor was completed — not just
the one path the normal login form walks you down. This is a common class of bug in
MFA implementations: the server tracks "is this session associated with a logged-in
user" correctly, but conflates that with "has this session completed every required
authentication stage," when those are two different things. Any session, cookie, or
token-based system that adds a second factor needs to encode *which* stages a given
session has passed, and every protected endpoint needs to check for the complete set
— not just "a user is attached to this session at all."

This also illustrates why client-side flow (redirects, hidden form steps, disabled
buttons) is never a substitute for server-side enforcement: a client can always choose
to send a different request than the one the UI offers.

## Remediation

- Store an explicit "MFA completed" flag on the server-side session, set only after a
  correct code is verified.
- Check that flag on *every* request to a protected resource — not just rely on the
  login page's redirect behavior to funnel users through the 2FA step.
- Treat a session that has passed only the password stage as not-yet-authenticated for
  all purposes until the second factor succeeds; don't issue it the same trust level as
  a fully authenticated session.
