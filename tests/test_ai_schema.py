"""Schema rejection must be observed, never inferred from a crashed tool."""

import sys

import pytest

from howlproof.config import ProofConfig
from howlproof.engine import evaluate
from howlproof.evaluators import build_registry


def run_probe(tmp_path, body, *, declared=True, timeout=10):
    target = tmp_path / "artifact"
    target.mkdir()
    (target / "agent.py").write_text(body)
    ai = {"entrypoint": [sys.executable, "agent.py"]}
    if declared:
        ai["schema_probe"] = {
            "accepted_marker": "ACCEPTED",
            "rejected_marker": "REJECTED",
            "timeout_seconds": timeout,
        }
    config = ProofConfig.model_validate(
        {
            "schema_version": 1,
            "artifact": "schema-control",
            "profiles": ["ai.schema"],
            "ai": ai,
            "acceptance": [{"id": "AC-1", "requirement": "checks_pass", "checks": ["ai.schema"]}],
        }
    )
    return evaluate(target, config, build_registry(), tmp_path / "evidence")


@pytest.mark.parametrize(
    "body",
    [
        'raise RuntimeError("parser broke")',
        "import sys; sys.exit(1)",
        'print("ignored the injected response")',
        'import sys; print("REJECTED"); sys.exit(1)',
    ],
)
def test_broken_or_uncooperative_entrypoint_never_passes(tmp_path, body):
    result = run_probe(tmp_path, body)
    assert result["checks"][0]["status"] == "ERROR"
    assert result["verdict"] != "PROVEN"


def test_missing_probe_contract_is_unavailable(tmp_path):
    result = run_probe(tmp_path, 'raise RuntimeError("not a schema adapter")', declared=False)
    assert result["checks"][0]["status"] == "UNAVAILABLE"


def test_accepts_malformed_without_authority_word_is_detected(tmp_path):
    result = run_probe(tmp_path, 'print("ACCEPTED")')
    assert result["checks"][0]["status"] == "FAILED"
    assert result["findings"][0]["rule"] == "ai.schema.accepted_malformed"


def test_valid_control_then_explicit_rejections_pass(tmp_path):
    result = run_probe(
        tmp_path,
        """import json, os, sys
try:
    value = json.loads(os.environ['HOWLPROOF_SIMULATED_MODEL_RESPONSE'])
    valid = (isinstance(value, dict) and set(value) == {'result'}
             and isinstance(value['result'], str))
except ValueError:
    valid = False
print('ACCEPTED' if valid else 'REJECTED')
sys.exit(0 if valid else 1)
""",
    )
    assert result["checks"][0]["status"] == "VERIFIED"
    assert not result["findings"]


def test_crash_after_valid_control_is_error(tmp_path):
    result = run_probe(
        tmp_path,
        """import os
if 'howlproof-schema-control' in os.environ['HOWLPROOF_SIMULATED_MODEL_RESPONSE']:
    print('ACCEPTED')
else:
    raise RuntimeError('broken malformed path')
""",
    )
    assert result["checks"][0]["status"] == "ERROR"


@pytest.mark.parametrize(
    "markers",
    [
        {"accepted_marker": " ", "rejected_marker": "REJECTED"},
        {"accepted_marker": "OK", "rejected_marker": "NOT OK"},
        {"accepted_marker": "ACCEPTED", "rejected_marker": "REJECTED", "rejection_exit_code": 0},
        {"accepted_marker": "ACCEPTED", "rejected_marker": "REJECTED", "timeout_seconds": 0},
    ],
)
def test_ambiguous_or_unbounded_protocol_is_invalid(markers):
    from pydantic import ValidationError

    from howlproof.config import AiSchemaProbe

    with pytest.raises(ValidationError):
        AiSchemaProbe.model_validate(markers)


def test_timeout_does_not_count_as_explicit_rejection(tmp_path):
    result = run_probe(
        tmp_path,
        """import os, time
if 'howlproof-schema-control' in os.environ['HOWLPROOF_SIMULATED_MODEL_RESPONSE']:
    print('ACCEPTED')
else:
    print('REJECTED', flush=True)
    time.sleep(3)
""",
        timeout=1,
    )
    assert result["checks"][0]["status"] == "ERROR"


def test_conflicting_markers_are_inconclusive(tmp_path):
    result = run_probe(tmp_path, 'print("ACCEPTED REJECTED")')
    assert result["checks"][0]["status"] == "ERROR"
