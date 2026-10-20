"""Execution ends descendants and drains service logs without blocking startup."""

import os
import signal
import socket
import sys
import time
from pathlib import Path

import pytest

from howlproof.config import ProofConfig
from howlproof.evaluators.pyenv import provision
from howlproof.evidence import Bundle
from howlproof.registry import Context
from howlproof.service import ServiceRunner
from howlproof.target import Target


def context_for(tmp_path, **settings):
    root = tmp_path / "target"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="fixture"\nversion="0.0.0"\n')
    target = Target.prepare(root, tmp_path / "workspace")
    config = ProofConfig.model_validate({"schema_version": 1, "artifact": "fixture", **settings})
    return Context(target, config, Bundle.create(tmp_path / "proof", root))


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def alive(pid):
    status = Path(f"/proc/{pid}/stat")
    return status.exists() and status.read_text().split()[2] != "Z"


def wait_dead(pid):
    deadline = time.monotonic() + 2
    while alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not alive(pid)


def child_code():
    return (
        "import subprocess,sys,pathlib; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "pathlib.Path('child.pid').write_text(str(child.pid)); "
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process lifecycle contract")
def test_command_timeout_ends_descendants(tmp_path):
    context = context_for(tmp_path)
    code = child_code() + "import time; time.sleep(60)"
    try:
        result = context.target.run([sys.executable, "-c", code], timeout=1)
        pid = int((context.target.workspace / "child.pid").read_text())
        assert result.timed_out
        wait_dead(pid)
    finally:
        path = context.target.workspace / "child.pid"
        if path.exists() and alive(int(path.read_text())):
            os.kill(int(path.read_text()), signal.SIGKILL)


def test_verbose_service_can_become_ready(tmp_path):
    port = unused_port()
    code = (
        "import sys; print('x'*1000000, flush=True); "
        "from http.server import ThreadingHTTPServer,SimpleHTTPRequestHandler; "
        f"ThreadingHTTPServer(('127.0.0.1',{port}),SimpleHTTPRequestHandler).serve_forever()"
    )
    context = context_for(
        tmp_path,
        service={
            "base_url": f"http://127.0.0.1:{port}",
            "start": [sys.executable, "-c", code],
            "ready_timeout_seconds": 3,
        },
    )
    with ServiceRunner(context) as service:
        assert service.running, service.note
    assert len(service.startup_log) <= 20000
    assert service.startup_log


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process lifecycle contract")
def test_service_stop_ends_descendants(tmp_path):
    port = unused_port()
    code = (
        child_code() + "from http.server import ThreadingHTTPServer,SimpleHTTPRequestHandler; "
        f"ThreadingHTTPServer(('127.0.0.1',{port}),SimpleHTTPRequestHandler).serve_forever()"
    )
    context = context_for(
        tmp_path,
        service={
            "base_url": f"http://127.0.0.1:{port}",
            "start": [sys.executable, "-c", code],
            "ready_timeout_seconds": 3,
        },
    )
    try:
        with ServiceRunner(context) as service:
            assert service.running
        pid = int((context.target.workspace / "child.pid").read_text())
        wait_dead(pid)
    finally:
        path = context.target.workspace / "child.pid"
        if path.exists() and alive(int(path.read_text())):
            os.kill(int(path.read_text()), signal.SIGKILL)


def test_python_provisioning_does_not_download_without_network_permission(tmp_path, monkeypatch):
    context = context_for(tmp_path)

    def unexpected_command(*args, **kwargs):
        pytest.fail("offline provisioning attempted to execute an installer")

    monkeypatch.setattr(context.target, "run", unexpected_command)
    result = provision(context)
    assert not result.ready
    assert "--allow-network" in result.reason


def test_service_workdir_must_be_relative():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ProofConfig.model_validate(
            {
                "schema_version": 1,
                "artifact": "fixture",
                "service": {
                    "base_url": "http://127.0.0.1:9876",
                    "workdir": "/outside",
                },
            }
        )


def test_command_workdir_cannot_follow_a_link_outside_workspace(tmp_path):
    from howlproof.target import TargetError

    context = context_for(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (context.target.workspace / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(TargetError, match="workspace"):
        context.target.run([sys.executable, "-c", "pass"], cwd_rel="linked")
