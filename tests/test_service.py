"""HTTP probes stay on the declared local surface, including redirects."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from howlproof.service import request


@contextmanager
def local_server():
    visited = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            visited.append(self.path)
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "/destination")
            self.end_headers()
            self.wfile.write(b"response")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", visited
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost.example.invalid",
        "http://127.0.0.1.example.invalid",
        "http://localhost@remote.invalid",
        "https://localhost",
        "http://127.0.0.10",
    ],
)
def test_request_rejects_hosts_that_only_share_a_local_prefix(url, monkeypatch):
    def unexpected_network(*args, **kwargs):
        pytest.fail("invalid destination reached the HTTP transport")

    monkeypatch.setattr("urllib.request.OpenerDirector.open", unexpected_network)
    with pytest.raises(ValueError, match="outside this machine"):
        request(url, "GET", "/")


def test_request_returns_redirect_without_following_it():
    with local_server() as (url, visited):
        response = request(url, "GET", "/redirect")
    assert response.status == 302
    assert visited == ["/redirect"]


def test_local_requests_ignore_environment_proxies(monkeypatch):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    with local_server() as (url, visited):
        response = request(url, "GET", "/")
    assert response.status == 200
    assert visited == ["/"]
