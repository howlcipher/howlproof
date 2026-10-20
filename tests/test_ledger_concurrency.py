"""Ledger identity and lifecycle survive overlapping processes and interrupted writes."""

import json
import multiprocessing

import pytest

from howlproof.ledger import Ledger, LedgerError
from howlproof.model import Adversary, Confidence, Finding, FindingState, Severity


def make_finding(title):
    return Finding(
        check_id="fixture.check",
        adversary=Adversary.SECURITY,
        category="security",
        title=title,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        summary=title,
        evidence="fixture observation",
        recommended_remediation="correct the fixture",
    )


def writer(root, barrier, index):
    ledger = Ledger.open(root)
    barrier.wait(timeout=10)
    ledger.assign("fixture", make_finding(f"defect {chr(65 + index)}"), f"run-{index}", "sha")
    ledger.save()


def test_parallel_writers_keep_every_finding(tmp_path):
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(6)
    workers = [context.Process(target=writer, args=(tmp_path, barrier, i)) for i in range(6)]
    for worker in workers:
        worker.start()
    try:
        for worker in workers:
            worker.join(timeout=20)
            assert worker.exitcode == 0
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join()
    entries = Ledger.open(tmp_path).entries()
    assert len(entries) == 6
    assert len({row["id"] for row in entries}) == 6


def test_stale_writer_does_not_erase_an_accepted_risk(tmp_path):
    first = Ledger.open(tmp_path)
    raised = first.assign("fixture", make_finding("one"), "first", "sha")
    first.save()
    stale = Ledger.open(tmp_path)
    first.record_state(
        "fixture",
        raised.id,
        FindingState.ACCEPTED_RISK,
        "accept",
        "The operator explicitly accepted this fixture risk.",
    )
    first.save()
    stale.assign("fixture", make_finding("two"), "later", "sha")
    stale.save()
    assert Ledger.open(tmp_path).get("fixture", raised.id)["state"] == "ACCEPTED_RISK"


def test_ids_are_unambiguous_across_artifacts(tmp_path):
    ledger = Ledger.open(tmp_path)
    one = ledger.assign("first", make_finding("one"), "run", "sha")
    two = ledger.assign("second", make_finding("two"), "run", "sha")
    assert one.id != two.id
    assert ledger.find_anywhere(two.id)[0] == "second"


def test_symlink_ledger_cannot_redirect_writes(tmp_path):
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text('{"schema": "howlproof.ledger/v1", "artifacts": {}}')
    (tmp_path / "ledger.json").symlink_to(elsewhere)
    with pytest.raises(LedgerError, match="symlink"):
        Ledger.open(tmp_path)


def test_interrupted_replace_preserves_the_previous_ledger(tmp_path, monkeypatch):
    ledger = Ledger.open(tmp_path)
    ledger.assign("fixture", make_finding("one"), "run", "sha")
    ledger.save()
    before = (tmp_path / "ledger.json").read_bytes()

    def fail_replace(*args, **kwargs):
        raise OSError("simulated interruption before atomic replace")

    monkeypatch.setattr("os.replace", fail_replace)
    with pytest.raises(OSError):
        ledger.assign("fixture", make_finding("two"), "run", "sha")
        ledger.save()
    assert (tmp_path / "ledger.json").read_bytes() == before
    assert len(Ledger.open(tmp_path).entries()) == 1


def test_legacy_duplicate_ids_require_artifact_scope(tmp_path):
    ledger = Ledger.open(tmp_path)
    ledger.assign("first", make_finding("one"), "run", "sha")
    ledger.assign("second", make_finding("two"), "run", "sha")
    ledger.save()
    data = json.loads((tmp_path / "ledger.json").read_text())
    for artifact in data["artifacts"].values():
        for finding in artifact["findings"].values():
            finding["id"] = "HP-SEC-0001"
    (tmp_path / "ledger.json").write_text(json.dumps(data))
    with pytest.raises(LedgerError, match="ambiguous"):
        Ledger.open(tmp_path).find_anywhere("HP-SEC-0001")


def abandon_transaction(root):
    import os

    ledger = Ledger.open(root)
    with ledger._update():
        os._exit(7)


def test_abrupt_process_exit_releases_the_lock(tmp_path):
    ledger = Ledger.open(tmp_path)
    ledger.assign("fixture", make_finding("before"), "run", "sha")
    context = multiprocessing.get_context("spawn")
    worker = context.Process(target=abandon_transaction, args=(tmp_path,))
    worker.start()
    worker.join(timeout=10)
    assert worker.exitcode == 7
    ledger.assign("fixture", make_finding("after"), "run", "sha")
    assert len(Ledger.open(tmp_path).entries()) == 2


def test_symlink_lock_is_refused(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("untouched")
    (tmp_path / "ledger.lock").symlink_to(elsewhere)
    with pytest.raises(LedgerError, match="lock"):
        Ledger.open(tmp_path).assign("fixture", make_finding("one"), "run", "sha")
    assert elsewhere.read_text() == "untouched"


def test_dismissal_without_a_reason_cannot_be_committed(tmp_path):
    ledger = Ledger.open(tmp_path)
    finding = ledger.assign("fixture", make_finding("one"), "run", "sha")
    with pytest.raises(LedgerError, match="reason"):
        ledger.record_state("fixture", finding.id, FindingState.WONT_FIX, "run", " ")
    assert Ledger.open(tmp_path).get("fixture", finding.id)["state"] == "FOUND"


def test_lock_contention_has_a_deadline(tmp_path, monkeypatch):
    import fcntl

    def busy(*args):
        raise BlockingIOError("held by another process")

    monkeypatch.setattr(fcntl, "flock", busy)
    monkeypatch.setattr("howlproof.ledger.LOCK_TIMEOUT", 0, raising=False)
    with pytest.raises(LedgerError, match="timed out"):
        Ledger.open(tmp_path).assign("fixture", make_finding("one"), "run", "sha")
