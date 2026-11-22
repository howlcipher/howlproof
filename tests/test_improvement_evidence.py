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
