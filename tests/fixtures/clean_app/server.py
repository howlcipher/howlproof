#!/usr/bin/env python3
"""The same HTTP surface as the vulnerable fixture, built correctly.

It exists so the live adversaries can be shown not to invent findings: every check
that fires against `vulnerable_app/server.py` must stay quiet here.

- /api/state refuses a privileged transition without authority
- /api/items rejects an unparsable body with a defined client error and no internals
- a repeated create is idempotent rather than a server error
"""

import json
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8732
CREATED: dict[str, dict] = {}
ITEMS: dict = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        return

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        # The interface is served from its own origin during an evaluation, as it is
        # in a real deployment, so the API has to allow it.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/api/list":
            self._send(200, json.loads(pathlib.Path("data/items.json").read_text()))
            return
        self._send(200, {"ok": True, "path": self.path})

    def do_POST(self) -> None:
        if self.path == "/api/seed":
            # Re-reads the item file, which is how an authored payload reaches the
            # interface without the evaluator touching the running process.
            ITEMS.clear()
            ITEMS.update(json.loads(pathlib.Path("data/items.json").read_text()))
            self._send(200, {"seeded": len(ITEMS.get("items", []))})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            self._send(413, {"error": "REQUEST_TOO_LARGE"})
            return
        raw = self.rfile.read(length)
        if self.path == "/api/state":
            # Authority is derived here, not assumed, and absence denies.
            self._send(403, {"error": "AUTHORITY_DENIED", "envelope_status": "ENVELOPE_ABSENT"})
            return
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            self._send(400, {"error": "INVALID_JSON"})
            return
        if not isinstance(body, dict):
            self._send(400, {"error": "EXPECTED_OBJECT"})
            return
        if self.path == "/api/items":
            identifier = str(body.get("id", "fixed"))
            record = CREATED.setdefault(identifier, {"id": identifier})
            self._send(200, record)
            return
        self._send(404, {"error": "NO_SUCH_ROUTE"})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"clean fixture listening on {PORT}", file=sys.stderr, flush=True)
    server.serve_forever()
