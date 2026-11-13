# Lab 02 — Profile bio moderation (Filtered Blind SSTI)

Harder than Lab 01. Do Lab 01 first.

## Run it

```bash
python3 app.py               # serves http://127.0.0.1:8000
python3 listener.py 9000     # second terminal — your OOB catcher
```

## The target

```
POST /profile       form field:  bio
```

Your bio is rendered server-side for "moderation" and the response is **always**
`{"status":"submitted for review"}`.

```bash
curl -s http://127.0.0.1:8000/profile --data-urlencode 'bio=hello'
```

## What's different (and harder)

1. A filter **rejects any input containing `{{` or `}}`**. Your Lab 01 payload
   will just bounce:
   ```bash
   curl -s http://127.0.0.1:8000/profile --data-urlencode 'bio={{7*7}}'
   # {"reason":"disallowed characters","status":"rejected"}
   ```
2. **No timing gift and no errors** leak — the response is identical every time.
   Detection *and* exfil must both go out-of-band.

## Your mission

Confirm execution and exfiltrate `flag.txt` — with **no `{{ }}`** and **no
reflected output**.

## Rules

- 90-minute timer. Solo. **No AI.**
- Open `INDEX.md` only after you've solved it or the timer's done.

Hint, one only: `{{ ... }}` prints a value. What's the *other* Jinja tag — the
one that runs logic but prints nothing?
