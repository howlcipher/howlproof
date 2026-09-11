#!/usr/bin/env python3
"""A deliberately defective HTTP service, so the live adversaries have something to catch.

Every fault here is planted. `tests/test_evaluators.py` asserts that each one is
found, and `tests/fixtures/clean_app/server.py` is the same surface built correctly
and must stay quiet.

- /api/state performs a privileged transition without checking authority at all
- /api/items returns 200 and an internal traceback when the body will not parse
- a repeated create fails with a server error instead of a defined client error
"""

import json
import pathlib
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8731
CREATED: set[str] = set()
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
        raw = self.rfile.read(length)
        if self.path == "/api/state":
            # The contract says a transition to EXECUTING requires authority. This
            # checks nothing, which is the defect http.authz exists to catch.
            self._send(200, {"state": "EXECUTING", "authorized": "not checked"})
            return
        try:
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise TypeError(f"expected an object, got {type(body).__name__}")
        except Exception:  # noqa: BLE001 - the planted defect is exactly this
            # Answers 200 and hands the caller an internal traceback.
            self._send(200, {"ok": True, "detail": traceback.format_exc()})
            return
        if self.path == "/api/items":
            identifier = str(body.get("id", "fixed"))
            if identifier in CREATED:
                self._send(500, {"error": "duplicate identifier", "id": identifier})
                return
            CREATED.add(identifier)
            self._send(201, {"id": identifier})
            return
        self._send(404, {"error": "no such route"})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"vulnerable fixture listening on {PORT}", file=sys.stderr, flush=True)
    server.serve_forever()
