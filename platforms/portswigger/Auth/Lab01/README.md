# Username Enumeration via Different Responses

**Category:** Authentication
**Difficulty:** Apprentice
**CWE:** CWE-203 (Observable Discrepancy) / CWE-307 (Improper Restriction of Excessive Authentication Attempts)

## Vulnerability Overview

Many login forms try to avoid leaking whether a given username exists by returning a
generic "invalid username or password" message on any failed login. This lab shows a
common way that protection fails in practice: the application returns two outwardly
similar, but **not byte-for-byte identical**, responses depending on whether the
submitted username is real.

The discrepancy can show up in several places, and it only takes one of them leaking
for the whole protection to fail:

- Different error text ("Invalid username" vs. "Invalid password")
- Different HTTP status code
- Different response length / word count / line count
- Different response timing (not the vector in this particular lab, but the same
  family of bug)
- Different headers or cookies set on the response

Once an attacker can reliably tell "username doesn't exist" apart from "username
exists, password is wrong," username enumeration becomes a simple wordlist attack
against the login endpoint. From there, the attack is two sequential brute-force
passes:

1. Fuzz a list of candidate usernames with a fixed, wrong password. Filter out the
   "no such user" response signature. Whatever survives the filter is a valid
   username.
2. Fix that username and fuzz a list of candidate passwords. Filter out the
   "wrong password" response signature (now that the username is confirmed valid).
   Whatever survives — typically a redirect to an authenticated page — is the correct
   password.

## Why This Matters

Username enumeration on its own is often treated as low severity, but it's rarely the
whole story — it's the reconnaissance step that makes a subsequent password
brute-force attack tractable. Without it, an attacker has to guess *both* a valid
username and its password simultaneously out of a combinatorial space. With it, the
two become independent, much smaller searches. This is also why many real-world
breaches start with cheap, automatable enumeration against a login form rather than
anything more sophisticated.

## Remediation

- Return an **identical** response for "no such user" and "wrong password" —
  same status code, same body (byte for byte), same headers, same timing (constant-time
  comparison / artificial delay), same cookies/lack thereof.
- Rate-limit and lock out based on IP and/or account after repeated failures, independent
  of which failure reason applies.
- Avoid timing differences introduced by doing extra work only on one branch (e.g.
  hashing a password only when the username is found — do a dummy hash either way).
