# HowlProof

Independent red-team QA, falsification and evidence for the Howl ecosystem.
Beta 0.2.0b1 for advisory evaluation of trusted local artifacts on Linux.

**Most QA asks whether the software works. HowlProof tries to prove that it doesn't.**

**HowlProof judges. It does not repair the artifact it is judging.**

[Website](https://howlcipher.github.io/howlproof/) ·
[Ecosystem](https://howlcipher.github.io/howl/ecosystem.html) ·
[CI](https://github.com/howlcipher/howlproof/actions/workflows/ci.yml)

## Why it exists

HowlBoard states the problem in its own domain model: a `claimed` result is one an
agent asserted and nothing independently confirmed. The ecosystem could turn
intent into code, route it, govern it and render it, but nothing in it was a
dedicated adversary whose job is to try to prove the result wrong.

HowlProof is that component. It challenges an artifact, tries to falsify it,
captures reproducible evidence, and issues a verdict that says exactly what was
and was not established.

| Traditional QA | HowlProof |
| --- | --- |
| Does this pass? | How can this fail, and can I prove the failure? |
| A green run means done | A green run means the checks that ran, ran |
| A skipped check is invisible | A skipped check is a recorded limitation |
| Fixes what it finds | Reports what it finds and re-verifies the repair |

## The five adversaries

| Adversary | The question it asks |
| --- | --- |
| Functional | What input, state or sequence makes this behave incorrectly? |
| Security | Where does the trust boundary not hold, and what can reach across it? |
| Reliability | What happens when a dependency, a restart or the stored state goes wrong? |
| AI | Can untrusted text become instruction, or malformed output become a trusted value? |
| Operator | What would a careful person get wrong, and what does the documentation promise that the code does not do? |

## Verdicts

| Verdict | Exit | Meaning |
| --- | --- | --- |
| `PROVEN` | 0 | Every acceptance criterion was satisfied, no unresolved finding sits above the permitted threshold, and enough checks actually executed to justify saying so |
| `CONDITIONALLY_PROVEN` | 10 | Passed subject to documented exclusions, environment limitations or unresolved non-blocking findings, each named in the result |
| `REQUIRES_HUMAN` | 20 | The evidence cannot safely support an autonomous decision |
| `REJECT` | 30 | Evidence demonstrates a violation of the criteria, security, reliability or policy |
| `INSUFFICIENT_EVIDENCE` | 40 | The evaluation that ran was inadequate to decide, so nothing is claimed |

Also `2` for a usage or configuration error, `3` for an internal fault, and `4`
when the artifact changed during its own evaluation. `--fail-under <verdict>`
collapses these for a pipeline that only wants pass or fail.

`INSUFFICIENT_EVIDENCE` is the point of the whole design. HowlProof prefers
saying it could not tell over implying that it checked.

## Quick start

```bash
git clone https://github.com/howlcipher/howlproof.git
cd howlproof
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
howlproof doctor
howlproof validate howlproof.yaml
howlproof evaluate tests/fixtures/vulnerable_app --evidence-root /tmp/proof
howlproof findings /tmp/proof
howlproof report /tmp/proof
```

`tests/fixtures/vulnerable_app` is a deliberately defective artifact in this
repository. With the required tooling available, the evaluation exits `30` and
reports planted defects across credentials, workflows, markup, documentation,
HTTP authorization and malformed input, AI handling, CLI behavior and browser
execution. Its neighbour `tests/fixtures/clean_app` has the same surfaces built
correctly, raises none of those findings, and is not rejected.

## Checks are not all the same kind of answer

| Status | Meaning |
| --- | --- |
| `VERIFIED` | The check ran and the artifact behaved as required |
| `FAILED` | The check ran and the artifact did not |
| `SKIPPED` | The check was deliberately not run, with a recorded reason |
| `UNAVAILABLE` | The tooling to run it was not present, with a recorded reason |
| `NOT_APPLICABLE` | The artifact has no such surface, with a recorded reason |
| `ERROR` | The evaluator itself failed, which is evidence about the evaluator |

Four of these are not passes and none of them is silent. Every check also records
a `limitation`: one sentence saying what it does **not** establish. A missing tool
never reads like a clean result.

## Findings

A finding carries a durable identifier (`HP-SEC-0041`), an adversary, an
`ai.review_finding/v1` severity, a confidence, evidence, a recommended
remediation, a fingerprint, and a lifecycle state:

```
FOUND → REPRODUCED → REMEDIATION_REQUESTED → RETESTED → VERIFIED_FIXED
        NOT_REPRODUCED   REGRESSED   ACCEPTED_RISK   WONT_FIX
```

The identifier is allocated once, on the first observation of a fingerprint, and
reused forever, so the same defect keeps its number across runs, commits and line
shifts.

Ledger mutations commit immediately under a POSIX file lock, using a private
temporary file, atomic replacement and filesystem sync. Overlapping local
processes reload the latest state before modifying it, so an old reader cannot
erase another evaluation or an accepted risk. New identifiers are unique across
artifacts within an evidence root. Existing identifiers are preserved; ambiguous
legacy IDs are refused rather than silently attributed to the first artifact.
Ledger writes currently require a local POSIX filesystem with working file locks;
Windows and network filesystem durability are not established.

`CONFIRMED` confidence is reserved for findings whose defect was directly
observed, and the model refuses to construct one without a recorded reproduction.

A finding on its own can only reject an artifact when it is both at or above the
blocking severity and `CONFIRMED`. A severe finding that was not reproduced
routes to `REQUIRES_HUMAN` instead, unless something earlier in the derivation
already decided: a violated acceptance criterion rejects regardless of whether any
finding was raised.

## Accepting a finding

A finding that an operator has examined and chosen to live with is recorded, not
deleted:

```bash
howlproof accept HP-SEC-0001 --reason "Authored fixture data; the value was never valid."
```

The reason is mandatory and checked for substance, mirroring HowlPlane's rule that
dismissing a blocker or high finding requires an explicit resolution reason. The
finding stops blocking verdicts, stays in the ledger with that reason attached, and
keeps appearing in every report. There is no way to make one disappear quietly.

## The falsification loop

```bash
howlproof reproduce HP-SEC-0001 --bundle proof --target ../artifact
# ... the repair happens in the artifact's own repository, by its builder ...
howlproof verify-fix HP-SEC-0001 --bundle proof --target ../artifact
```

`verify-fix` refuses to answer when the artifact's tree digest is identical to the
state the finding was raised against, because an unchanged artifact cannot have
been fixed. When the artifact has changed it re-runs the evaluator that raised the
finding. If that evaluator could not run, the absence of the finding is reported
as inconclusive rather than as a fix.

Fix verification binds the artifact identity and original tree digest to the
loaded evidence bundle, even when the original ledger is absent. JSON output
states `lifecycle_recorded` separately from the verification outcome, so an
imported bundle cannot silently update an unrelated ledger finding with the same
legacy ID. Replay is also invalidated if the original target changes, with exit 4.
Workspace preparation refuses an artifact edited while its files are copied.

A statement that a defect was repaired never produces `VERIFIED_FIXED`. Only a
re-execution does.

## Evidence

```
proof/hp-20260911-143000-2f0c9a17b4d5/
  manifest.json     howlproof.run/v1, authority ADVISORY, implementation hash, file hashes
  target.json       repo, commit, branch, dirty, tree digest before and after
  environment.json  every tool probed, and why an absent one is absent
  checks.jsonl      each check with its checker version, status, mode and limitation
  findings/HP-SEC-0001.json
  reproductions/HP-SEC-0001/steps.json
  evidence/<check-id>/...     raw output, HTTP transcripts, screenshots
  result.json       howlproof.result/v1: verdict, deciding rule, criteria table
  result.md         the same, for a human
  handoff.json      howlproof.handoff/v1, advisory
```

`howlproof inspect <bundle>` re-reads the bundle and recomputes every hash in its
own integrity index. A bundle that has been edited does not load.

Evidence is written **outside** the artifact by default. Writing it inside is
refused unless `--allow-evidence-in-target` is passed, because an evaluator that
leaves files in its subject has changed the thing it was measuring.

## Profiles

```bash
howlproof profiles
howlproof profiles security
howlproof evaluate . --profile python --profile security
howlproof evaluate . --profile secrets.scan     # a single evaluator, by name
```

`default`, `code`, `python`, `go`, `api`, `web`, `ai`, `security`, `reliability`,
`documentation`, `release`. Profiles are YAML data inside the package, so they can
be read and tested rather than inferred. Third-party evaluators register through
the `howlproof.evaluators` entry-point group.

## Reproducible source calibration

```bash
howlproof calibrate calibration.json --evidence-root /tmp/howlproof-calibration > calibration-report.json
```

The versioned corpus has ten clean/defective cases for `secrets.scan`,
`ci.supplychain`, `markup.escaping` and `release.version`. The report records
expected and observed rules, per-rule true/false positive and negative counts,
inconclusive cases, input tree digests, implementation hashes and fresh evidence
bundle paths. Exit 0 means all labels matched, 30 means a mismatch and 40 means
some cases could not be evaluated. Missing coverage never contributes a true
negative. These are synthetic fixture measurements, not an estimate of detection
accuracy on arbitrary software. Corpus labels are human-authored and must be
reviewed rather than regenerated from current detector output.

## Concurrent create checks

The API profile includes `api.concurrency`, enabled only when an artifact declares
an endpoint that creates a distinct resource for each distinct request key:

```yaml
api:
  concurrent_create:
    path: /api/items
    body: {name: probe}
    request_id_field: request_key
    id_field: id
    requests: 10
    workers: 4
```

Each POST receives a fresh request key in the named body field. The endpoint must
return a JSON object carrying a string or integer ID. The check detects duplicate
response IDs across successful creates. Failed requests, invalid JSON and missing
IDs produce `ERROR`, never a clean uniqueness result. Requests are bounded to
100, workers to 16, and each HTTP call has a ten-second timeout. This is a single
burst against the service started in the workspace; it does not establish absence
of lost updates or durable storage. Use `requirement: checks_pass` with `checks: [api.concurrency]` in an
acceptance criterion when successful execution of this check is required.

## Acceptance criteria

An artifact declares its own contract in `howlproof.yaml`. Validation is strict:
unknown keys, wrong types and unknown enum values are rejected rather than
ignored, because a typo that silently disables a criterion is worse than no
criterion.

```yaml
schema_version: 1
artifact: howlboard
profiles: [code, api, web, security]
blocking_severity: HIGH
acceptance:
  - {id: AC-01, requirement: checks_pass,       checks: [go.test, go.vet]}
  - {id: AC-02, requirement: max_findings,      adversary: SECURITY, min_severity: HIGH, limit: 0}
  - {id: AC-03, requirement: tool_required,     tools: [go]}
  - {id: AC-04, requirement: no_regressions}
  - {id: AC-05, requirement: required_evidence, artifacts: [web.responsive/index-375.png]}
  - {id: AC-06, requirement: coverage_floor,    min_conclusive_fraction: 0.7}
exclusions:
  - {check: deps.audit, reason: "No network access in this environment.", expires: 2026-12-01}
```

`tool_required` is the important one: a named tool that is absent is a hard
failure, never a silent skip. Any active exclusion prevents `PROVEN` and an
expired one routes to `REQUIRES_HUMAN`.

A bundle loader rejects unindexed files and symbolic links, including links to
files inside the bundle. Required-evidence criteria inspect files actually written,
not just references returned by a check. Duplicate check identifiers and runs with
no completed applicable check cannot support a positive verdict. `verify-fix`
requires the original check to return `VERIFIED` against a target whose digest
remained unchanged during the rerun.

## Security model

Security evaluation is defensive, bounded and authorised. HowlProof probes
artifacts an operator points it at, on the operator's own machine.

- HTTP requests are refused unless the destination is `127.0.0.1` or `localhost`,
  both in the configuration schema and again at the call site.
- Managed package downloads and dependency auditing require `--allow-network`.
  Without it, Python environment provisioning reports `UNAVAILABLE` and dependency
  auditing reports `SKIPPED`, with reasons.
- Artifact commands run with the operator's host permissions and inherited
  environment. The workspace copy and digest guard are not an OS sandbox and do
  not prevent commands from using the network. Evaluate trusted commands only;
  put untrusted executables in an independently managed disposable sandbox.
- On POSIX hosts, commands and services start in dedicated process groups.
  Timeouts and shutdown clean up descendants remaining in those groups. Service
  output is drained continuously with only its last 20,000 characters retained.
  Process-group cleanup does not contain code that deliberately escapes it.
  Lifecycle tests treat a disappearing process entry as completed cleanup.
  A missing service working directory is recorded as an unavailable service.
- Injection payloads are authored, declared in the artifact's own configuration,
  and written into the workspace copy, never the artifact.
- Credentials found by `secrets.scan` are reported by shape and length, not
  reprinted. Everything written into a bundle passes through redaction first.
- No exploitation tooling ships with the package, and no evaluator attempts
  persistence, lateral movement or anything against a host the operator did not
  name.

## Separation of duties, enforced in code

This is what makes HowlProof more than a test runner with branding.

1. Evaluators never receive a writable handle to the artifact. The tree is
   materialised into a workspace copy and every command runs there.
2. The artifact's file set and contents are digested before evaluation and
   re-discovered afterwards. Any modification, addition or removal raises a
   `BLOCKER` integrity finding, forces `INSUFFICIENT_EVIDENCE` and exits `4`.
3. Evidence is written outside the artifact by default.

The test suite includes an evaluator that deliberately writes into its target, and
asserts that the evaluation is invalidated rather than reported as a pass.

## Ecosystem integration

`howlproof handoff <bundle> --for <target>` writes a file in a schema a sibling
already reads. These are documented file contracts, not native API integrations,
and no sibling component requires a change to consume them.

| Target | Emits | Read by |
| --- | --- | --- |
| `plane` | `ai.review_finding/v1` YAML | `python -m src.control_plane reconcile --findings-file` |
| `board` | `ai.evidence_entry/v1` JSONL | HowlBoard's `make import`, via HowlPlane's evidence ledger |
| `relay` | Markdown under HowlRelay's recognised headings | HowlRelay's continuity collector |
| `verification-plan` | `ai.verification_plan/v1` | HowlPlane's verification artifacts |
| `changeops` | A human-readable advisory | Nothing. HowlChangeOps has no ingest path for an external verdict, and the file says so |

Every handoff carries `authority: ADVISORY`. HowlProof issues verdicts; HowlPlane
decides what to do about them and HowlChangeOps owns promotion and rollback.

These are tested rather than asserted. `tests/test_handoff.py` validates every
emitted document against a vendored copy of HowlPlane's published JSON Schema,
which is closed and rejects unknown fields. Two of the three emitters failed that
test when it was first written and were corrected; the `plane` handoff was also
run end to end through HowlPlane's own `reconcile --findings-file`.

## Limitations

- Beta scope is trusted local artifacts on Linux. Hostile-code isolation and
  production-wide detection accuracy are not established.
- Static analysis shows that an escaper's character set is wrong for a context.
  It does not prove a value reaches that context. The browser-level
  `web.dom_injection` check exists to close that gap, and needs a running service
  and a declared payload.
- `ai.promptinjection` runs a fixed corpus of five strings. Model behaviour is not
  deterministic between runs, so a clean result is reported at the confidence it
  deserves and a finding from it is never `CONFIRMED`.
- `reliability.corrupt_store` injects the fault it observes, so it is recorded as
  `SIMULATED`. The artifact's reaction to it is a real observation.
- Rendered checks need Playwright and Chromium. Without them the result is
  `UNAVAILABLE`, which means the site has not been shown to work at any width.
- HowlProof evaluates artifacts on the machine it runs on. It is not a hosted
  service and has no scheduler.
- CLI tests run in subprocesses, so ordinary in-process coverage does not capture
  their execution. Python environment provisioning and external dependency audits
  also need explicit network permission; fixture calibration does not establish
  those integrations work in every environment.
- The synthetic source corpus covers ten cases across four evaluators. It
  reports per-rule confusion counts for those cases only. It does not measure
  real-world accuracy or calibrate the other evaluators.

## Non-goals

- **HowlProof is not an autonomous repair agent.** It never edits the artifact it
  evaluates. Remediation is routed through HowlPlane to the appropriate builder.
- It does not decide what gets built. That is HowlPlane.
- It does not execute, promote or roll back change. That is HowlChangeOps.
- It does not monitor continuous security posture. That boundary is documented for
  a future HowlGuard and deliberately not built here.
- It is not a general fact oracle, a fuzzing campaign, or a replacement for review
  by a person.

## Testing

`tests/fixtures/` ships three artifacts, and the suite runs the evaluators against
all of them.

`vulnerable_app` carries planted defects across every adversary: a
committed credential, four workflow weaknesses, an escaper that is wrong for the
context and an HTML sink with none at all, a documented sync that has drifted,
broken links, missing metadata, rendering defects, and a live HTTP service that
authorises a privileged transition without checking, hands back a traceback on
malformed input and errors on a repeated create. It also ships an AI entry point
that obeys injected instructions and accepts malformed model output, a command
line that exits zero on invalid input, and an interface a real browser confirms is
injectable by executing an authored payload.

`clean_app` is the same surface built correctly. Every check that fires against
the vulnerable fixture must stay silent here, and a test asserts it raises nothing
at all: a check that fires on a correct artifact is as useless as one that never
fires.

`version_drift` is a three-file package that disagrees with itself about its
version.

The suite also registers an evaluator that deliberately writes into its target and
asserts the evaluation is invalidated, and drives the real command line with an
artifact whose own declared command edits itself mid-evaluation, asserting exit
code 4. Every emitted ecosystem handoff is validated against a vendored copy of
HowlPlane's closed JSON Schema.

```bash
python -m playwright install chromium   # the browser checks need one
pytest -q                       # the whole suite
pytest -q tests/test_verdict.py # the verdict table alone
pytest -q -k dom_injection      # the browser-level injection check, both ways
```

The browser-dependent tests fail rather than skip when no browser is installed.
A check that never ran is not a pass, and a skip is the kind of thing nobody
notices.

## Development

```bash
pip install -e '.[dev]'
ruff format --check src tests
ruff check src tests
flake8 src tests --max-line-length=100 --extend-ignore=E203,W503
mypy
pytest -q
howlproof doctor
howlproof validate howlproof.yaml
howlproof calibrate calibration.json --evidence-root /tmp/howlproof-calibration
howlproof evaluate tests/fixtures/clean_app --evidence-root /tmp/howlproof-clean --fail-under CONDITIONALLY_PROVEN
python -m build
bandit -r src -ll
pip-audit --skip-editable
python -m playwright install chromium
python scripts/check_site.py
python scripts/test_seo.py
```

These are the same commands CI runs.

## Documentation

- [The contract](docs/contract.md) — what HowlProof owns and what it does not
- [Ecosystem boundaries](docs/ecosystem.md) — how it sits beside ChangeOps, Plane and a future HowlGuard
- [Evaluators](docs/evaluators.md) — every check, what it establishes and what it does not
- [Dogfood](docs/dogfood.md) — real evaluations of real ecosystem components
- [Roadmap](ROADMAP.md)
- [Readiness and remaining work](docs/readiness.md)

MIT licensed. Beta for trusted local artifacts on Linux.

## Plane CLI integration

Proof has a CLI and versioned JSON/file contracts. To ingest a specific sealed
bundle into Plane's existing reconciler:

```bash
howlproof plane /absolute/path/to/proof/hp-RUN-ID --run-dir /tmp/plane-proof-run
```

The run directory must be new and outside the bundle. The command verifies bundle
integrity before invoking `howlplane reconcile`, records the advisory verdict,
command, original result (including unavailable checks), exit codes and report,
and times out after 120 seconds. Use `--timeout`
or `--executable` for another bound or Plane installation. It never grants
promotion authority. Proof verdict exits remain nonzero even when reconciliation
succeeds; a Plane blocker returns 1 when Proof's verdict exit is zero. Tool or
protocol errors return 2 with an error record when the run directory was created.

The bridge ingests an existing evaluation; it does not re-evaluate the target or
establish that an old bundle describes today's working tree. Evaluate the repaired
artifact afresh before ingestion. There is no HTTP service. For remote untrusted
artifacts, OS isolation and authenticated provenance remain outstanding.

Cross-repository check:

```bash
HOWLPROOF_PLANE=$(command -v howlplane) pytest -q tests/test_plane_bridge.py
python scripts/check_ecosystem_contracts.py --plane-root ../howlplane
```

## Evidence authenticity

Manifest hashes detect changes. Optional detached SSH signatures also let a
consumer authenticate who signed that exact manifest. Choose a key explicitly:

```bash
howlproof attest /path/to/hp-RUN-ID --key /path/to/signing-key --output /path/to/run.sig
howlproof verify-attestation /path/to/hp-RUN-ID --signature /path/to/run.sig \
  --allowed-signers /path/to/allowed-signers --identity proof-ci
```

The allowed-signers file is consumer-owned OpenSSH policy, for example
`proof-ci namespaces="howlproof-evidence" ssh-ed25519 PUBLIC_KEY`. Distribute
trusted public keys independently of received evidence. OpenSSH `ssh-keygen`
with SSH signature support is required. Signing never selects an ambient key;
protected keys need an already-authorized SSH agent. Interactive prompts are
disabled and operations have a 30-second deadline. Output must be a new file
outside the bundle and evaluated target; signatures do not alter sealed bundles.

Verification checks both bundle integrity and the signature in the
`howlproof-evidence` namespace. Exit 0 authenticates the recorded evidence; the
JSON still carries its original advisory verdict. It does not establish that
an old run describes today's target, detector accuracy, or permission to promote.
Invalid signatures return 4; missing/invalid input follows the usual CLI errors.
Key issuance, revocation and allowed-signers maintenance belong to the consumer.

For authenticated Plane ingestion, pass `--signature`, `--allowed-signers` and
`--identity` together to `howlproof plane`. Authentication must succeed before
Plane starts or its run directory is created. The run record includes the
verified identity and manifest hash. Without these flags, ingestion records that
authentication was not requested and retains the trusted-local-artifact scope.

The markup sink heuristic now stops at JavaScript sink-call and statement
boundaries, so nearby unrelated escape calls cannot hide defects and unrelated
HTML construction cannot create findings. Independent regression fixtures cover
both errors. This remains bounded lexical scanning: aliases, branches, cross-file
flows and complete JavaScript grammar still require deeper analysis.

## AI schema adapter protocol

`ai.schema` v2 tests a closed object with exactly one string field, `result`.
Declare how the local entry point reports acceptance and rejection:

```yaml
ai:
  entrypoint: [python3, agent.py]
  schema_probe:
    accepted_marker: "accepted result:"
    rejected_marker: "rejected:"
    rejection_exit_code: 1
    timeout_seconds: 10
```

The adapter must read `HOWLPROOF_SIMULATED_MODEL_RESPONSE`. Proof first sends
`{"result":"howlproof-schema-control"}` and requires exit 0 with the acceptance
marker on stdout. It then sends five malformed responses. Rejection requires the
declared nonzero exit and rejection marker; crashes, timeouts, conflicting markers
and unexplained outputs are inconclusive errors. Acceptance of malformed output
raises a finding even without authority-shaped text. Transcripts retain expected
and observed outcomes, including the valid control.

Markers must be nonblank and non-overlapping. Per-call timeouts are bounded to
1–60 seconds. Without `schema_probe`, the check reports `UNAVAILABLE`; an
uncooperative entry point cannot establish parser correctness. This is a local
adapter test, not a live-model benchmark or a general JSON-schema validator.
