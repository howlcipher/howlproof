"""Parallel create probes detect colliding IDs without inventing success on errors."""

import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Barrier, Lock, Thread

import pytest
from pydantic import ValidationError

from howlproof.config import ProofConfig
from howlproof.evaluators import build_registry
from howlproof.evidence import Bundle
from howlproof.model import CheckStatus
from howlproof.registry import Context
from howlproof.target import Target


@contextmanager
def create_service(behavior):
    counter = 0
    lock = Lock()
    rendezvous = Barrier(4)
    request_ids = set()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            nonlocal counter
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            with lock:
                request_ids.add(payload["howlproof_request_id"])
            # Every group must overlap; serial execution cannot pass this fixture.
            rendezvous.wait(timeout=3)
            with lock:
                counter += 1
                identifier = counter if behavior == "unique" else 1
            self.send_response(500 if behavior == "error" else 201)
            self.end_headers()
            payload = {} if behavior == "missing" else {"id": identifier}
            self.wfile.write(json.dumps(payload).encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
        assert len(request_ids) == 8
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize(
    "behavior,status,findings",
    [
        ("unique", CheckStatus.VERIFIED, 0),
        ("collision", CheckStatus.FAILED, 1),
        ("error", CheckStatus.ERROR, 0),
        ("missing", CheckStatus.ERROR, 0),
    ],
)
def test_concurrency_checks_real_parallel_responses(tmp_path, behavior, status, findings):
    root = tmp_path / "target"
    root.mkdir()
    config = ProofConfig.model_validate(
        {
            "schema_version": 1,
            "artifact": "fixture",
            "api": {"concurrent_create": {"path": "/items", "requests": 8, "workers": 4}},
        }
    )
    target = Target.prepare(root, tmp_path / "workspace")
    context = Context(target, config, Bundle.create(tmp_path / "proof", root))
    with create_service(behavior) as url:
        context.service_base_url = url
        context.service_running = True
        outcome = build_registry().get("api.concurrency").evaluate(context)
    assert outcome.checks[0].status is status
    assert len(outcome.findings) == findings
    target.verify_unchanged()
    assert outcome.checks[0].evidence_refs


@pytest.mark.parametrize(
    "settings",
    [
        {"path": "http://remote.invalid"},
        {"path": "/items", "requests": 101},
        {"path": "/items", "workers": 0},
        {"path": "/items", "id_field": ""},
    ],
)
def test_concurrency_config_is_bounded(settings):
    with pytest.raises(ValidationError):
        ProofConfig.model_validate(
            {"schema_version": 1, "artifact": "fixture", "api": {"concurrent_create": settings}}
        )
