# Walkthrough — 2FA Simple Bypass

## Credentials given
- Attacker-controlled: `wiener:peter`
- Victim (target account): `carlos:montoya`

## Tools used
- `curl` — isolating and testing the session cookie at each login stage
- Browser — final confirmation by direct URL navigation

## Step 1 — Understand the two-stage flow first

Before attacking anything, the flow needs mapping:
1. `POST /login` with username + password → on success, redirects to `/login2`
2. `POST /login2` with an `mfa-code` → on success, redirects to `/my-account`

The question worth asking up front: is the session cookie issued after step 1 already
"fully authenticated," or does the server track a separate internal flag for "passed
password, not yet passed 2FA"? That's not something you can answer by reading the UI —
it has to be tested directly against the server.

## Step 2 — Isolate the cookie from each stage with curl

```bash
# Step A: password-only login, into its own cookie jar
curl -i -c step1_cookies.txt -X POST 'https://<lab-id>.web-security-academy.net/login' \
  --data-urlencode 'username=carlos' \
  --data-urlencode 'password=montoya'
```

Inspecting the response and `step1_cookies.txt` shows a `session` cookie value issued
right after the password check succeeds — *before* any mfa-code has been submitted.

**Important gotcha hit while testing:** reusing the same cookie jar across both the
login and the `/login2` request (`-b cookies.txt -c cookies.txt` on both) overwrites
the jar each time `-c` runs. That makes it easy to accidentally test the *post-2FA-attempt*
cookie instead of the *post-password, pre-2FA* cookie you actually meant to test. The
fix is using a dedicated jar for the password step and never touching it with a later
`/login2` call:

```bash
# Step B: using ONLY the step-1 cookie, request the account page directly —
# do not submit an mfa-code with this cookie first
curl -i -b step1_cookies.txt 'https://<lab-id>.web-security-academy.net/my-account'
```

## Step 3 — Confirm in the browser

The same result is reproducible without curl: log in normally with `carlos:montoya`,
and once redirected to the 2FA entry page, manually edit the URL from `/login2` to
`/my-account` instead of entering a code. The account page loads directly.

This confirms the account page's authentication check only verifies "does this
session belong to a logged-in user," not "has this session's user completed the
2FA stage." The redirect to `/login2` is purely a client-side navigation choice made
by the login page — nothing enforces it server-side.

## Step 4 — Solve confirmed

Landing on Carlos's `/my-account` page without ever submitting an mfa-code solves the
lab.

## Key takeaways

- **A redirect is not an access control.** The server sending your browser to
  `/login2` next doesn't mean anything stops you from requesting `/my-account`
  instead — redirects are a client-side navigation hint, never an enforcement
  mechanism, unless the destination endpoint independently re-checks authorization.
- **Session state needs to track *which stages* were completed**, not just "is a user
  attached to this session." A session half-way through a multi-step flow should carry
  a distinct, lower trust level than a fully-authenticated one, and every protected
  endpoint needs to check for that explicitly.
- **Cookie jar discipline matters when isolating multi-stage state.** Reusing `-b`/`-c`
  against the same file across sequential requests silently overwrites earlier state —
  use separate jars (or inspect the jar's contents between steps) whenever you need to
  test a specific intermediate session value rather than whatever the jar currently
  holds.
- **Test the hypothesis directly, not just by inference.** Knowing the cookie values
  differ between stages tells you nothing on its own — the only way to know whether the
  earlier one is already privileged is to send it to the protected resource and see what
  comes back.
