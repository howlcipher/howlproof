"""Bringing the artifact up, and talking to it.

Live adversaries need a running artifact. It is started inside the workspace copy,
never the original tree, and a failure to start is recorded as an unavailable
surface rather than quietly treated as nothing to test.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters for type checking
    from howlproof.registry import Context

DEFAULT_HTTP_TIMEOUT = 15

#: Requests only ever reach an artifact this evaluation started on this machine.
LOCAL_PREFIXES = ("http://127.0.0.1", "http://localhost")


@dataclass
class HttpResponse:
    status: int
    body: str
    headers: dict[str, str]
    elapsed_ms: int
    error: str = ""

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "headers": self.headers,
            "body": self.body[:20_000],
            "error": self.error,
        }


def request(
    base_url: str,
    method: str,
    path: str,
    body: Any = None,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_HTTP_TIMEOUT,
    raw_body: bytes | None = None,
    content_type: str = "application/json",
) -> HttpResponse:
    """One HTTP call against the artifact under evaluation, never following redirects."""
    url = base_url.rstrip("/") + path
    payload = raw_body
    if payload is None and body is not None:
        payload = json.dumps(body).encode()
    sent_headers = {"Content-Type": content_type} if payload is not None else {}
    sent_headers.update(headers or {})
    if not url.startswith(LOCAL_PREFIXES):
        raise ValueError(
            f"refusing to send an evaluation request outside this machine: {url}. "
            "HowlProof attacks artifacts the operator started locally, not remote hosts."
        )
    call = urllib.request.Request(url, data=payload, headers=sent_headers, method=method)
    started = time.monotonic()
    try:
        # The scheme and host are restricted to a locally started artifact by the check
        # above and by the base_url pattern the configuration already enforces.
        with urllib.request.urlopen(call, timeout=timeout) as response:  # nosec B310
            content = response.read().decode("utf-8", errors="replace")
            return HttpResponse(
                status=response.status,
                body=content,
                headers=dict(response.headers.items()),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
    except urllib.error.HTTPError as error:
        content = error.read().decode("utf-8", errors="replace")
        return HttpResponse(
            status=error.code,
            body=content,
            headers=dict(error.headers.items()) if error.headers else {},
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except (urllib.error.URLError, OSError, ValueError) as error:
        return HttpResponse(
            status=0,
            body="",
            headers={},
            elapsed_ms=int((time.monotonic() - started) * 1000),
            error=f"{type(error).__name__}: {error}",
        )


def port_is_free(base_url: str) -> bool:
    parts = urlsplit(base_url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 80
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(2)
        return probe.connect_ex((host, port)) != 0


class ServiceRunner:
    """Context manager that starts the artifact's service in the workspace copy."""

    def __init__(self, context: Context) -> None:
        self.context = context
        self.config = context.config.service
        self.process: subprocess.Popen[str] | None = None
        self.running = False
        self.note = ""
        self.base_url = self.config.base_url if self.config else ""
        self.startup_log = ""

    def __enter__(self) -> Self:
        if self.config is None or not self.config.start:
            self.note = "no service is declared, so live adversaries have nothing to attack"
            return self
        if not port_is_free(self.config.base_url):
            self.note = (
                f"{self.config.base_url} is already in use; refusing to attack a process this "
                "evaluation did not start"
            )
            return self
        workdir = self.context.target.workspace / self.config.workdir
        try:
            self.process = subprocess.Popen(
                list(self.config.start),
                cwd=str(workdir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except (OSError, ValueError) as error:
            self.note = f"service failed to start: {type(error).__name__}: {error}"
            return self
        if self._await_ready():
            self.running = True
            self._seed()
        else:
            self.note = (
                f"service did not become ready at {self.config.ready_path} within "
                f"{self.config.ready_timeout_seconds}s"
            )
            self.stop()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _await_ready(self) -> bool:
        assert self.config is not None
        deadline = time.monotonic() + self.config.ready_timeout_seconds
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                self.startup_log = self._drain()
                return False
            probe = request(
                self.config.base_url,
                self.config.ready_method,
                self.config.ready_path,
                body={} if self.config.ready_method == "POST" else None,
                timeout=3,
            )
            if probe.status and probe.status < 500:
                return True
            time.sleep(0.25)
        return False

    def _seed(self) -> None:
        assert self.config is not None
        if not self.config.seed:
            return
        method, _, path = self.config.seed[0].partition(" ")
        response = request(self.config.base_url, method or "POST", path or "/", body={})
        if response.status >= 400 or response.error:
            self.note = f"seed request returned {response.status or response.error}"

    def _drain(self) -> str:
        if self.process is None or self.process.stdout is None:
            return ""
        try:
            return self.process.stdout.read()[-20_000:]
        except (OSError, ValueError):
            return ""

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.startup_log = self.startup_log or self._drain()
        self.process = None
        self.running = False

    def restart(self) -> bool:
        """Stop and start again, for the reliability adversary's recovery probe."""
        self.stop()
        entered = self.__enter__()
        return entered.running
