# Readiness and remaining work

HowlProof 0.2.0b1 is a beta for advisory evaluation of trusted local artifacts on
Linux. A passing suite establishes tested contracts; it does not establish
detector accuracy on arbitrary artifacts. The beta adds explicit concurrency and
execution boundaries plus a repeatable synthetic source calibration baseline.

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
| Partially complete | Measure evaluator accuracy | A versioned ten-case clean/defective corpus reports per-rule counts for four source evaluators. Expand coverage and add independent holdouts before general accuracy claims |
| Partially complete | Artifact execution | POSIX descendant cleanup, bounded service logs and managed-download permission are tested; commands retain host permissions and environment, and hostile-code containment requires a separate sandbox |
| Implemented and gated | Operator onboarding | `init` creates an explicit, non-overwriting contract; draft acceptance cannot pass. CI installs the wheel outside the checkout and exercises the first-project CLI workflow on supported Python versions |
| Completed locally | Concurrent ledger writers | Six overlapping processes retain distinct findings and IDs; stale-writer and interrupted-replacement contracts pass on a local POSIX filesystem |
| 2 | Trace markup dataflow | Follow source values and aliases into sinks across statements; demonstrate known bypasses and clean-context fixtures without claiming whole-program analysis |
| Partially complete | Calibrate AI probes | Schema v2 uses a valid-response control and labelled adapter outcomes; explicit rejection differs from crash, timeout or ignored simulation. Benign prompt-injection controls, repeated model trials and uncertainty measurement remain open |
| 2 | Detect lost updates | Add declared state observations before and after parallel mutations and compare expected state deltas, alongside response-ID checks |
| 2 | Inject dependency faults | Exercise an explicitly declared local dependency through timeout, disconnect and invalid-response faults; keep simulation labels precise |
| Partially complete | Authenticate exported evidence | Detached SSH manifest signatures and explicit allowed-signers policy reject changed evidence, reindexed forgeries and unknown identities. Key provisioning, rotation and revocation procedures remain consumer-owned |
| 3 | Replay ecosystem regressions | Re-evaluate previously fixed findings across explicitly selected artifact revisions, preserving new evidence separately from historical bundles |
| 3 | Validate real outcomes | Compare advisory verdicts with later observed defects before making claims about production readiness or detection rates |

Uncompleted rows are acceptance targets. Signing requires
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

Runtime hardening verification: 215 tests passed in 98.98 seconds on Python
3.14.4. Tests reproduce noisy startup, timeout/shutdown descendants, forbidden
working directories and unauthorized Python downloads. Ruff, flake8, mypy,
generated documentation and source/wheel builds passed. Bandit's medium/high
gate now completes without the prior suppression warnings.

## Beta qualification contract

The supported beta is the advisory CLI and evidence workflow on Linux with a local
POSIX filesystem and operator-trusted commands. Python 3.11 through 3.14 must pass
the CI matrix before integration. The release gate includes strict input/status
contracts, known-defect and clean-artifact runs, integrity and ecosystem handoff
checks, concurrent ledger recovery, process lifecycle tests, source calibration,
packaging, dependency audit and rendered-site QA.

The `calibration.json` v2 baseline covers four named source evaluators, ten artifact
cases and eight rule labels. It includes separate markup fixtures for statement
boundary regressions. Confusion counts are reported per rule; cases without a
rule remain negative labels, and inconclusive execution never counts as a pass.
All ten case labels match on the synthetic corpus. The cases
are authored regression fixtures, not an independent holdout or representative
sample. No percentage from these cases is advertised as general detector accuracy.

Remaining roadmap work does not disappear with beta: dataflow, AI controls,
lost-update observations, dependency fault injection, key lifecycle policy, independent
holdouts and outcome calibration remain explicit. A beta verdict is still
advisory, and HowlProof still does not repair artifacts or authorize deployment.

Beta candidate verification: 226 tests passed in 104.04 seconds on Python 3.14.4.
The built wheel was installed into a separate directory, loaded from that
installation, and passed all eight source calibration cases with all 29 evaluator
registrations and packaged profiles available. Release-version checking accepts
its matching 0.2.0b1 declarations. Site QA, SEO, generated docs, Ruff, flake8,
mypy, dependency audit, source/wheel builds and the configured Bandit gate passed.

Final beta boundary gate: 233 tests passed in 102.41 seconds on Python 3.14.4.
Fix verification now uses the original bundle's artifact identity and tree digest,
refuses a missing baseline, and cannot close an unrelated legacy ledger ID.
Replay invalidates mutation of the original, workspace copying refuses concurrent
edits, and missing service directories remain explicit unavailable surfaces.
Combined line/branch coverage is 78%; subprocess-driven CLI paths remain partly
outside that measurement. The final installed wheel passed the eight-case corpus;
fresh smoke evidence is under `/tmp/howlproof-final-wheel-hjihxw6_`.
