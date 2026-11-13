#!/usr/bin/env python3
# =====================================================================
# Blind SSTI — Lab 02: "Profile bio moderation" (filtered + pure blind)
# ---------------------------------------------------------------------
# VULNERABLE BY DESIGN. Run ONLY inside an isolated VM (host-only / NAT).
# Never expose this to a real network. It grants remote code execution.
# ---------------------------------------------------------------------
# Harder than Lab 01, two ways:
#   1. A crude "WAF" rejects any input containing {{ or }} (the output
#      tags). You cannot use {{ ... }} at all.
#   2. There is NO timing side channel handed to you and the response is
#      always identical. Detection and exfil must both go out-of-band.
#
# Goal: confirm execution and exfiltrate flag.txt with no reflected
# output and no {{ }}.
# =====================================================================
import os
from flask import Flask, request, jsonify
from jinja2 import Environment

app = Flask(__name__)
FLAG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt")

BLOCKLIST = ("{{", "}}")  # the "WAF"


@app.route("/")
def index():
    return (
        "Blind SSTI Lab 02 - Profile bio moderation\n"
        "\n"
        "  POST /profile   form field: bio\n"
        "\n"
        "Your bio is rendered server-side for moderation. A filter\n"
        "rejects output tags. The response is always the same.\n"
    )


@app.route("/profile", methods=["POST"])
def profile():
    bio = request.form.get("bio", "")

    # ---- crude WAF ---------------------------------------------------
    if any(tok in bio for tok in BLOCKLIST):
        return jsonify(status="rejected", reason="disallowed characters"), 400

    # ---- THE VULNERABILITY -------------------------------------------
    # `bio` is rendered by a non-sandboxed Jinja2 Environment. Output is
    # discarded (moderation runs internally) -> blind SSTI. Because {{ }}
    # is filtered, you must drive execution with statement tags {% %}.
    template_source = "User bio: " + bio
    try:
        env = Environment()
        env.from_string(template_source).render()  # result intentionally discarded
    except Exception:
        pass  # errors swallowed: no error-based oracle either
    # ------------------------------------------------------------------

    return jsonify(status="submitted for review")


if __name__ == "__main__":
    if not os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, "w") as fh:
            fh.write("flag{f1ltered_bl1nd_ssti_statement_tags_ftw}\n")
    print("[*] Lab 02 listening on http://127.0.0.1:8000  (VULNERABLE - isolated VM only)")
    app.run(host="127.0.0.1", port=8000)
