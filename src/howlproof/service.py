"""Bringing the artifact up, and talking to it.

Live adversaries need a running artifact. It is started inside the workspace copy,
never the original tree, and a failure to start is recorded as an unavailable
surface rather than quietly treated as nothing to test.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from threading import Thread
from typing import IO, TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit

from howlproof.process import stop

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters for type checking
    from howlproof.registry import Context

DEFAULT_HTTP_TIMEOUT = 15

#: Requests only ever reach an artifact this evaluation started on this machine.
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
    parts = urlsplit(url)
    if (
        parts.scheme != "http"
        or parts.hostname not in LOCAL_HOSTS
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError(
            f"refusing to send an evaluation request outside this machine: {url}. "
            "HowlProof attacks artifacts the operator started locally, not remote hosts."
        )
    call = urllib.request.Request(url, data=payload, headers=sent_headers, method=method)
    started = time.monotonic()
    try:
        # Ignore ambient proxies and return redirects as evidence without following them.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(call, timeout=timeout) as response:  # nosec B310
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
        self.log_reader: Thread | None = None

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
        workdir = self.context.target.working_directory(self.config.workdir)
        try:
            self.process = subprocess.Popen(
                list(self.config.start),
                cwd=str(workdir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                start_new_session=os.name == "posix",
            )
        except (OSError, ValueError) as error:
            self.note = f"service failed to start: {type(error).__name__}: {error}"
            return self
        self.startup_log = ""
        assert self.process.stdout is not None
        self.log_reader = Thread(target=self._capture_log, args=(self.process.stdout,), daemon=True)
        self.log_reader.start()
        try:
            if self._await_ready():
                self.running = True
                self._seed()
            else:
                self.note = (
                    f"service did not become ready at {self.config.ready_path} within "
                    f"{self.config.ready_timeout_seconds}s"
                )
                self.stop()
        except BaseException:
            self.stop()
            raise
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

    def _capture_log(self, stream: IO[str]) -> None:
        try:
            while chunk := stream.read(4096):
                self.startup_log = (self.startup_log + chunk)[-20_000:]
        except (OSError, ValueError):
            pass
        finally:
            stream.close()

    def _drain(self) -> str:
        return self.startup_log

    def stop(self) -> None:
        if self.process is None:
            return
        stop(self.process)
        if self.log_reader is not None:
            self.log_reader.join(timeout=3)
        self.process = None
        self.running = False

    def restart(self) -> bool:
        """Stop and start again, for the reliability adversary's recovery probe."""
        self.stop()
        entered = self.__enter__()
        return entered.running
