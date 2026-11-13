#!/usr/bin/env python3
# =====================================================================
# OOB listener - your out-of-band callback catcher.
# This is your free, self-hosted replacement for Burp Collaborator.
# Run it in a second terminal, then make the target call back to it.
# Every request (path, query, headers, body) is printed with a time.
#   python3 listener.py            # default port 9000
#   python3 listener.py 9001       # custom port
# =====================================================================
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer


class Catcher(BaseHTTPRequestHandler):
    def _log(self):
        ts = datetime.now().strftime("%H:%M:%S")
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("latin-1") if length else ""
        print(f"\n[{ts}] >>> OOB CALLBACK <<<")
        print(f"  {self.command} {self.path}")
        if body:
            print(f"  body: {body}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _log
    do_POST = _log

    def log_message(self, *a):  # silence the default noisy logging
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    print(f"[*] OOB listener on http://127.0.0.1:{port}  (watching for callbacks)")
    HTTPServer(("127.0.0.1", port), Catcher).serve_forever()
