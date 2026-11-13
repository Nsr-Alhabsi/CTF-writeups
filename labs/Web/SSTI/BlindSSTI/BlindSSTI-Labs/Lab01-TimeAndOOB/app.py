#!/usr/bin/env python3
# =====================================================================
# Blind SSTI — Lab 01: "Feedback service"
# ---------------------------------------------------------------------
# VULNERABLE BY DESIGN. Run ONLY inside an isolated VM (host-only / NAT).
# Never expose this to a real network. It grants remote code execution.
# ---------------------------------------------------------------------
# Scenario: a feedback endpoint renders an internal greeting template
# server-side (for "logging"), but returns only a queued status. The
# rendered output is NEVER sent back to you -> the SSTI is BLIND.
#
# Your job: confirm the injection with no reflected output, then read
# and exfiltrate flag.txt through an out-of-band channel.
# =====================================================================
import os
from flask import Flask, request, jsonify
from jinja2 import Environment

app = Flask(__name__)
FLAG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt")


@app.route("/")
def index():
    return (
        "Blind SSTI Lab 01 - Feedback service\n"
        "\n"
        "  POST /feedback   form fields: name, message\n"
        "\n"
        "The server renders an internal greeting for logging but only\n"
        "returns {\"status\":\"queued\"}. Output is never reflected.\n"
    )


@app.route("/feedback", methods=["POST"])
def feedback():
    name = request.form.get("name", "anonymous")
    message = request.form.get("message", "")

    # ---- THE VULNERABILITY -------------------------------------------
    # User-controlled `name` is concatenated into a template string and
    # rendered by a non-sandboxed Jinja2 Environment. The result is
    # "logged" server-side and never returned -> blind SSTI.
    template_source = "Hi " + name + ", thanks for your feedback!"
    try:
        env = Environment()
        rendered = env.from_string(template_source).render()
        app.logger.info("internal greeting rendered: %r", rendered)  # not returned
    except Exception as exc:  # errors are swallowed too
        app.logger.info("render failed: %s", exc)
   # ------------------------------------------------------------------

    return jsonify(status="queued")


if __name__ == "__main__":
    if not os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, "w") as fh:
            fh.write("flag{bl1nd_ssti_t1me_then_00b_exfil}\n")
    print("[*] Lab 01 listening on http://127.0.0.1:8000  (VULNERABLE - isolated VM only)")
    app.run(host="127.0.0.1", port=8000)
