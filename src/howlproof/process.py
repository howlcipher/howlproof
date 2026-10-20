"""Lifecycle cleanup for commands and services started in dedicated sessions."""

from __future__ import annotations

import os
import signal
import subprocess


def stop(process: subprocess.Popen[str], *, timeout: int = 10, kill: bool = False) -> None:
    """Reap the leader and stop descendants remaining in its POSIX process group.

    This is lifecycle management, not a sandbox: hostile code can escape a group.
    """
    if os.name == "posix":
        _signal_group(process.pid, signal.SIGKILL if kill else signal.SIGTERM)
    elif process.poll() is None:
        process.kill() if kill else process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            _signal_group(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=timeout)
    finally:
        if os.name == "posix":
            _signal_group(process.pid, signal.SIGKILL)


def _signal_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass
