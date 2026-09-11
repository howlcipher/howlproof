# Changelog

## 0.1.0

Initial release. Strict versioned evaluation contracts with typed acceptance
criteria, twenty-eight evaluators across five adversaries, a six-value check
status vocabulary that keeps unavailable and skipped work distinguishable from a
pass, and a five-value verdict model that prefers INSUFFICIENT_EVIDENCE to a
claim the evaluation cannot support.

Separation of duties is enforced in code rather than documented: evaluators work
in a materialised copy, the artifact's file set and contents are digested before
and after, and any modification raises a blocking integrity finding that
invalidates the run. Evidence bundles are written outside the artifact, carry an
integrity index over every file, and refuse to load once edited.

Findings carry durable identifiers allocated from a fingerprint ledger, so the
same defect keeps its number across runs and commits. CONFIRMED confidence
requires a recorded reproduction. verify-fix refuses to answer when the artifact
has not changed and re-runs the evaluator when it has; a claim that something was
repaired never produces VERIFIED_FIXED on its own.

Ecosystem integration is by documented file contract into schemas HowlPlane,
HowlBoard and HowlRelay already read, so no sibling component changes. There is
no HowlChangeOps ingest path for an external verdict and the handoff for it says
so plainly rather than implying one exists. HowlGuard is not built; only the
boundary is written down.
