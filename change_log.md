# Changelog

## Unreleased

Added `howlproof interop --json`: the `howl.interop/v1` descriptor from the Howl
interop contract, built from the live parser, with the verdict exit table and
the `howlplane reconcile` command `howlproof plane` runs, so `howl doctor` can
check that edge against the installed HowlPlane.

Added `howlproof init` for validated starter contracts with explicit selected-check
requirements, private exclusive writes and protection for existing config names
and links. Drafts without operator-specified acceptance cannot reach PROVEN.
Bare target names with spaces or punctuation now get valid default identities.
CI now installs the built wheel in a fresh environment and exercises initialization,
evaluation, integrity inspection, report export and detection of a subsequent defect
outside the source checkout on each supported Python version.

Fixed `ai.schema` false passes when an entry point crashes, times out, ignores
simulation or silently fails. Checker v2 requires a valid-response control and an
explicit bounded acceptance/rejection adapter protocol. Missing declarations are
UNAVAILABLE. Malformed acceptance no longer depends on an authority keyword.
Rejection markers inside exceptions or additional diagnostic output cannot pass.
Transcripts label expected and observed outcomes; fixtures declare their protocol.

Fixed markup false negatives from unrelated later escape calls and false positives
from unrelated later HTML construction. JavaScript sink scanning now respects
call/statement boundaries and quoted semicolons. Added separate defective/clean
fixtures to source corpus v2 (ten cases). This remains lexical analysis rather
than inter-statement taint tracking.

Added optional detached SSH manifest signatures with explicit key selection,
consumer-owned allowed-signers policy, a dedicated signature namespace and bounded
noninteractive operations. Verification authenticates intact evidence while retaining
its original advisory verdict. Tests reject tampering, reindexed forgeries and
untrusted identities. This provides authenticity, not execution isolation.

Added `howlproof plane` to verify an exact sealed bundle and ingest advisory
findings through Plane’s existing CLI with timeout cleanup, fresh run records
and preserved verdict exits. Added pinned real-CLI integration for rejection,
repair, unavailable required tools and tampered evidence. Refreshed Plane schemas
and added semantic drift detection with scheduled upstream checks. Corrected
stale experimental status in the ecosystem documentation.

## 0.2.0b1

Beta for trusted local artifacts on Linux. The advisory core now has durable
concurrent identity, bounded process lifecycle cleanup and a reproducible source
calibration command. The eight-case labelled corpus reports per-rule confusion
counts for four static evaluators and fails on missed defects, unexpected rules
or inconclusive execution. Reports bind labels, source trees and implementation
hashes to fresh evidence. This does not establish real-world detector accuracy,
hostile-code isolation or calibration of every evaluator.

Fix verification now binds artifact identity and tree state to its original
bundle rather than depending on the original ledger. Lifecycle updates require a
matching fingerprint and report whether they were recorded. Replay invalidates
original-target mutation, and workspace preparation refuses concurrent edits.

Release hygiene now accepts matching prerelease changelog headings. Quick-start
documentation describes fixture surfaces without stale fixed finding counts.

Lifecycle probes tolerate a process disappearing while its state is read; live
descendants still fail the cleanup contract. A missing service workdir is
reported as an unavailable surface instead of aborting evaluation.

Commands and services now run in dedicated POSIX sessions, with descendant
cleanup on timeout and shutdown. Service logs are drained continuously into a
bounded tail so verbose startup cannot deadlock a pipe. Working directories must
stay inside the workspace even through links. Managed Python provisioning now
requires --allow-network before any package installation. The documentation
explicitly distinguishes these controls from an OS sandbox and requires trusted
artifact commands.

Finding ledger writes now reload under a POSIX process lock and commit atomically
with file and directory sync. Concurrent evaluations cannot overwrite each
other's findings or lifecycle decisions. IDs are allocated across artifacts in
one evidence root, while legacy IDs remain unchanged and ambiguous lookups fail
explicitly. Symlink ledgers are rejected before resolving them. Regression tests
exercise six overlapping processes, stale writers and interrupted replacements.

Added `api.concurrency` to the API profile: bounded parallel creates carrying
unique request keys, evidence for every response, and duplicate-ID detection.
Real local service fixtures require overlapping requests and exercise clean,
colliding, failed and incomplete responses. This checks identifier uniqueness;
lost-update testing remains open.

Corrected false positive verification paths: absent evidence references cannot
satisfy required-evidence criteria; duplicate check IDs and runs with no completed
applicable check cannot produce positive verdicts; and verify-fix requires the
original check to verify on a target that stayed unchanged during evaluation.
AI prompt-injection probes no longer pass when their entry point fails or times out.

HTTP probes validate exact local hostnames, ignore ambient proxies and return
redirects without following them. Bundle loading rejects unindexed additions,
internal symlinks and malformed manifest types. Nested evidence files named
manifest.json are now included in the integrity index.

Every correction was reproduced by a failing regression test before implementation.

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

Dogfooding against HowlBoard and against HowlProof itself found five defects in
the evaluator before the committed runs. The injection check left its payload in
the workspace so another check reported the file as drifted; a payload that never
reached the rendered page was reported as safe rather than unavailable, which is
the exact failure this project exists to avoid; a required tool was reported
absent because a criterion guessed its version flag; workspace path containment
resolved symlinks and so rejected the interpreter the evaluation provisions for a
Python artifact; and the bundle integrity index hashed decoded text, so two
different screenshots could hash alike. All five are fixed with tests.

`accept` records a decision to live with a finding. The reason is mandatory and
checked for substance, the finding stops blocking, and it stays in the ledger and
in every report. There is no way to dismiss one quietly.

Ecosystem integration is by documented file contract into schemas HowlPlane,
HowlBoard and HowlRelay already read, so no sibling component changes. Those
contracts are tested rather than asserted: every emitted document is validated
against a vendored copy of HowlPlane's closed JSON Schema. Two of the three
emitters failed that test when it was first written, inventing fields their
readers reject, and were corrected. The findings handoff was additionally run end
to end through HowlPlane's own reconcile command, which accepted it. There is no
HowlChangeOps ingest path for an external verdict and the handoff for it says so
plainly rather than implying one exists. HowlGuard is not built; only the boundary
is written down.
