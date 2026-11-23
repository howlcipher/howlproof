"""Regression evidence must explicitly account for every required check."""

import pytest

from howlproof.improvement import REGRESSIONS, validate_regression_report


def test_accepts_executed_regressions():
    cases = "".join(
        f'<testcase classname="{module}" name="{name}" />' for module, name in sorted(REGRESSIONS)
    )
    validate_regression_report(f"<testsuites><testsuite>{cases}</testsuite></testsuites>".encode())


@pytest.mark.parametrize(
    "report",
    (
        b"<testsuites>",
        b"<!DOCTYPE testsuites><testsuites />",
        b"<testsuites><testsuite><testcase name='test_pdf_renderer' /></testsuite></testsuites>",
        b"<testsuites><testsuite><testcase><skipped /></testcase></testsuite></testsuites>",
    ),
)
def test_refuses_incomplete_or_unsupported_reports(report):
    with pytest.raises(ValueError):
        validate_regression_report(report)


def test_docx_profile_requires_fidelity_and_format_specific_regressions():
    from howlproof.improvement import DOCX_PROFILE, validate_sample

    checks = {"heading": True, "adjacent_paragraph": False, "reference": True}
    baseline = {"event": {}, "checks": checks, "producer": "python-docx"}
    validate_sample(baseline, DOCX_PROFILE, fixed=False)
    with pytest.raises(ValueError, match="disagrees"):
        validate_sample(baseline, DOCX_PROFILE, fixed=True)
    with pytest.raises(ValueError, match="disagrees"):
        validate_sample(baseline | {"producer": "Skia/PDF"}, DOCX_PROFILE, fixed=False)
    with pytest.raises(ValueError, match="disagrees"):
        validate_sample(baseline | {"checks": checks | {"heading": 1}}, DOCX_PROFILE, fixed=False)

    def report(cases):
        body = "".join(f'<testcase classname="{module}" name="{name}" />' for module, name in cases)
        return f"<testsuites><testsuite>{body}</testsuite></testsuites>".encode()

    validate_regression_report(report(DOCX_PROFILE.regressions), DOCX_PROFILE.regressions)
    with pytest.raises(ValueError, match="missing or duplicated"):
        validate_regression_report(report(REGRESSIONS), DOCX_PROFILE.regressions)
    required = sorted(DOCX_PROFILE.regressions)
    with pytest.raises(ValueError, match="missing or duplicated"):
        validate_regression_report(report(required + required[:1]), DOCX_PROFILE.regressions)


def test_refuses_detached_or_miscounted_testcases():
    cases = "".join(
        f'<testcase classname="{module}" name="{name}" />' for module, name in sorted(REGRESSIONS)
    )
    for payload in (
        f'<testsuites><testsuite tests="0" />{cases}</testsuites>',
        f'<testsuites><testsuite tests="0">{cases}</testsuite></testsuites>',
        f'<testsuites tests="0"><testsuite>{cases}</testsuite></testsuites>',
        f'<testsuites failures="1"><testsuite>{cases}</testsuite></testsuites>',
        f"<testsuites><metadata><testsuite>{cases}</testsuite></metadata></testsuites>",
    ):
        with pytest.raises(ValueError):
            validate_regression_report(payload.encode())
