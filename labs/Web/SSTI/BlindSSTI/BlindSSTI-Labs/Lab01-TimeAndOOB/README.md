# Lab 01 — Feedback service (Blind SSTI)

## Run it

```bash
pip install flask            # if you haven't
python3 app.py               # serves http://127.0.0.1:8000
```

In a **second terminal**, start your out-of-band catcher:

```bash
python3 listener.py 9000     # your free "Collaborator" on :9000
```

## The target

```
POST /feedback      form fields:  name, message
```

The service renders an internal greeting template server-side (for "logging")
but only ever returns `{"status":"queued"}`. **The rendered output is never
shown to you.**

Example request:

```bash
curl -s http://127.0.0.1:8000/feedback \
  --data-urlencode 'name=Nasser' --data 'message=hi'
```

## Your mission

1. Prove the `name` field is injected into a server-side template — **without**
   any reflected output to confirm it.
2. Escalate to command execution.
3. Read `flag.txt` (it sits next to `app.py`) and get its contents **out** of the
   server, even though you can't see command output on the page.

## Rules

- 90-minute timer. Solo. **No AI.** `curl` + `listener.py` only.
- Don't open `INDEX.md` until you've solved it or the timer's done.

Hint, one only: if you can't *see* the answer, make the server **tell you** —
either by how long it takes to reply, or by making it call you back.
