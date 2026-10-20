# Readiness and remaining work

HowlProof remains experimental. A passing test suite establishes the tested
contracts; it does not establish detector accuracy on arbitrary artifacts.

## Completed hardening

The current change closes reproduced failures in local HTTP destination checking,
redirect handling, evidence index completeness, symbolic-link rejection, malformed
manifest handling, nested manifest indexing, required-evidence existence, duplicate
check identifiers, empty conclusive coverage, fix verification, and failed AI probe
execution. Each behavior has a regression test that failed before its correction.

`api.concurrency` adds an opt-in bounded parallel-create probe. Its local fixtures
require actual request overlap and test both unique and colliding response IDs.
Errors and missing identifiers cannot be mistaken for successful uniqueness tests.
The check does not infer storage durability or lost-update safety.

## Work required for broader readiness

| Priority | Work | Completion evidence |
| --- | --- | --- |
| 1 | Measure evaluator accuracy | A versioned labelled corpus with clean and defective cases, per-evaluator false-positive and false-negative counts, and repeatable runs |
| 1 | Harden artifact execution | Document and test the trust boundary for artifact commands, subprocess descendants, inherited environment and network access; a workspace copy is not an OS sandbox |
| Completed locally | Concurrent ledger writers | Six overlapping processes retain distinct findings and IDs; stale-writer and interrupted-replacement contracts pass on a local POSIX filesystem |
| 2 | Trace markup dataflow | Follow source values and aliases into sinks across statements; demonstrate known bypasses and clean-context fixtures without claiming whole-program analysis |
| 2 | Calibrate AI probes | Add benign controls, labelled outcomes and repeated trials; distinguish application refusal from a broken entry point and report measured uncertainty |
| 2 | Detect lost updates | Add declared state observations before and after parallel mutations and compare expected state deltas, alongside response-ID checks |
| 2 | Inject dependency faults | Exercise an explicitly declared local dependency through timeout, disconnect and invalid-response faults; keep simulation labels precise |
| 3 | Authenticate exported evidence | Define key ownership and verification policy, sign a canonical bundle index, and test tampering, unknown keys and revoked keys |
| 3 | Replay ecosystem regressions | Re-evaluate previously fixed findings across explicitly selected artifact revisions, preserving new evidence separately from historical bundles |
| 3 | Validate real outcomes | Compare advisory verdicts with later observed defects before making claims about production readiness or detection rates |

These are acceptance targets, not implemented capabilities. Signing also requires
an owner's key and trust policy; outcome calibration requires observed outcomes.
No unattended repair, deployment or authority over sibling projects is added.

## Verification

Use the commands under Development in README.md. The CI matrix covers Python
3.11 through 3.14; a local run on one interpreter does not establish the entire
matrix. Browser checks require an installed Chromium. Dependency auditing queries
advisory data and must be reported separately from offline test results.

Test impact: the change affects evaluation orchestration, verdict derivation,
evidence loading, fix verification, local HTTP requests and evaluator registration.
The full suite is required because these are shared trust boundaries. New tests
protect observable failures, including real local HTTP responses and concurrent
creates. Existing CLI, clean/defective artifact and ecosystem handoff tests remain
relevant and are retained.

Local verification for this change (Python 3.14.4): 199 tests passed in 94.98
seconds. Ruff formatting and lint, the CI flake8 invocation, mypy, generated
evaluator documentation, source distribution and wheel builds passed. The site
passed browser checks at 375, 768 and 1440 pixels and its SEO checks. Dependency
auditing reported no known vulnerabilities after upgrading pip and urllib3 in the
project's development environment. Bandit's configured medium/high gate found no
issues; it still emits existing suppression-comment warnings in model.py, so this
is not a claim of a warning-free security scan. The other Python versions require
the CI matrix.

The final CLI smoke run rejected vulnerable_app with exit 30, returned
CONDITIONALLY_PROVEN for clean_app with exit 10, and returned
INSUFFICIENT_EVIDENCE for an artifact with no contract with exit 40. Both fixture
bundles passed integrity loading and rendered all five ecosystem handoffs. Fresh
evidence is under `/tmp/howlproof-final-smoke-jd35y67j`; historical bundles were
not edited.

Ledger hardening verification: 209 tests passed in 97.67 seconds on Python
3.14.4, including ten new concurrency, recovery and lifecycle contracts.
