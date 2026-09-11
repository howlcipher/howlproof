# Dogfood

Real evaluations of real ecosystem components, with the bundles committed beside
this document. Nothing here is a summary of a run that was not kept.

## HowlBoard

**Run** `hp-20260911-133826-ddbaef4e94e2` · **artifact** commit
`56246a9b47b0fe0b829756069fa70764a42c7213` · **verdict** `REJECT` ·
**bundle** [`dogfood/howlboard/`](../dogfood/howlboard)

### Why HowlBoard

It is runnable locally, it publishes a site, it exposes an HTTP API with a real
authority model, and its documentation makes several absolute claims. That gives
the functional, security, reliability and operator adversaries something to do,
and gives the evaluation something to be wrong about.

The evaluation contract lives in `dogfood/howlboard/howlproof.yaml` and was
**authored by HowlProof for this dogfood**, not by HowlBoard. The bundle records
that in `config.json`. Nothing was added to the HowlBoard repository to make this
evaluation possible.

### What the evaluation established

| | |
| --- | --- |
| Acceptance criteria satisfied | 6 of 7 |
| Checks | 12 verified, 4 failed, 0 skipped, 1 unavailable, 3 not applicable, 0 errored |
| Validation mode | 19 real, 1 simulated |
| Findings | 9, of which 1 blocking |

**Claims that held.** `docs/architecture.md` states that authority is computed on
every read rather than replayed from storage, and that a mission cannot enter
`EXECUTING` without live delegated authority. Both were probed directly against a
running instance:

- a transition to `EXECUTING` with no approval at all was refused `403 AUTHORITY_DENIED`
- an approval minted already expired, then used immediately, was refused `403` with `ENVELOPE_EXPIRED`

That second probe is the interesting one. It is specifically an attempt to defeat
the "computed on every read" claim by planting authority the storage layer would
happily hold. The claim survived.

Also verified: seven malformed request bodies were rejected cleanly with the
service still answering afterwards; three truncated or invalid connections did
not take it down; a clean restart recovered with state intact; all fifty site
references resolve; the published site carries complete discovery metadata; and
the file HowlBoard documents as kept in sync with its fixtures is in fact
identical to them.

**HP-SEC-0007, the blocking finding.** HowlBoard's escape function handles `&`,
`<`, `>` and `"` and does not handle the single quote. One of its call sites
places the escaped value inside a single-quoted JavaScript string in an
event-handler attribute. Escaping the double quote prevents breaking out of the
attribute; it does not prevent breaking out of the string, and the HTML parser
decodes the attribute before JavaScript parses it.

Static analysis raised this at `HIGH` confidence as `HP-SEC-0006`. It became
`CONFIRMED` only when a real browser loaded HowlBoard's own compiled interface
against a locally started instance, with an authored identifier placed in the
fixture its seed endpoint reads, and the injected expression executed. A
confirmed finding at `HIGH` is what produced the rejection.

Identifiers created through `/api/missions/create` are server assigned as
`HB-<n>`, so the API path does not carry this. The reachable paths are `/api/seed`
and the offline ledger importer, which both keep whatever identifier the source
document carried, and the importer's source is projected HowlPlane telemetry.

**Other findings.** Three GitHub Actions pinned to mutable tags, a workflow with
no `permissions:` block, one HTML sink built from an interpolated value with no
escape function in the expression, a horizontal scroll on the published site at
375px, and eighteen unqualified absolute claims in the documentation raised at
`INFORMATIONAL` so they are visible without blocking.

### What the evaluation did **not** establish

- `sast.bandit` was `UNAVAILABLE`: HowlBoard is not a Python package, so its
  source was not statically analysed by that tool.
- `deps.audit`, `cli.destructive` and `release.version` were `NOT_APPLICABLE`.
  HowlBoard declares no Python dependencies, no destructive subcommands and no
  `pyproject.toml` version.
- `reliability.corrupt_store` is `SIMULATED`. The corruption was injected by the
  evaluator into the workspace copy. The artifact's reaction to it — refusing to
  start, with a diagnostic — is a real observation of a simulated fault.
- The AI adversary did not run. HowlBoard declares no AI entry point, which is
  the honest answer rather than a passing check.
- Concurrency was not tested. HowlBoard documents a non-atomic `_seq` counter, and
  nothing in this evaluation exercised it. That documented limitation is
  unchallenged by this run.

### The loop, end to end

The remediation was made in HowlBoard's own repository, by a change to
`frontend/mission_view.howl` and `frontend/app.howl`: identifiers moved out of
event-handler attributes into `data-mission-id`, where escaping the quote
characters is sufficient, and each handler became a constant that reads the value
back with `this.dataset`. HowlProof did not make that change.

| Stage | What happened | Bundle |
| --- | --- | --- |
| `FOUND` | `markup.escaping` read HowlBoard's escape function, found it omits the single quote, and located a call site placing its output in a JavaScript string. `HP-SEC-0006`, `HIGH` confidence | `hp-20260911-133826-ddbaef4e94e2` |
| `REPRODUCED` | A real browser executed the payload against the compiled interface. `HP-SEC-0007`, `CONFIRMED` | same |
| `REMEDIATION_REQUESTED` | [howlboard#5](https://github.com/howlcipher/howlboard/pull/5), with the evidence bundle cited | — |
| `VERIFIED_FIXED` | `verify-fix` confirmed the tree digest had changed, re-ran `web.dom_injection`, and the payload no longer executed | `hp-20260911-135058-acbea8a02413` |
| `VERIFIED_FIXED` | The same for `HP-SEC-0006`, re-running `markup.escaping` | `hp-20260911-135257-e7c81bc63b96` |
| Re-evaluation | The full contract re-run: `CONDITIONALLY_PROVEN`, 7 of 7 acceptance criteria satisfied, both `HIGH` findings gone | `hp-20260911-135132-6a31b5f84f36` |

The tree digests recorded in the fix bundles differ from the state the findings
were raised against (`e5a9f720…` before, `d2205a2d…` after), which is what allowed
`verify-fix` to answer at all. Against an unchanged tree it refuses.

Note what the ledger does **not** do. The five remaining `MEDIUM` findings still
read `FOUND` after a full re-evaluation that no longer raises two of them, because
a finding disappearing from a later run is not evidence that it was repaired. Only
`verify-fix`, which re-runs the specific evaluator against a changed artifact,
moves a finding to `VERIFIED_FIXED`.

### Three defects this dogfood found in HowlProof

Pointing the evaluator at a real artifact broke the evaluator in three ways, all
fixed before the committed run:

1. **The injection check poisoned a file another check then read.** `web.dom_injection`
   wrote its payload into the workspace copy of `data/fixtures/missions.json` and
   left it there, so `docs.claims` reported the file as having drifted from its
   published copy. One check's input had become another check's finding. The
   payload is now restored after each attempt.
2. **A payload that never arrived was reported as safe.** The browser probe clicked
   the first five clickable elements, which were page chrome rather than mission
   rows, and reported "rendered as data, not executed". It now targets elements
   carrying a handler first, and separately records whether the payload reached the
   page at all: a payload that never arrived is `UNAVAILABLE`, not a pass.
3. **A required tool was reported absent because it was probed wrongly.** A
   `tool_required` criterion naming a tool no selected evaluator used fell back to
   `<tool> --version`, and `go --version` exits 2. Criteria now reuse the probe the
   registry already knows.

The second of those is the one worth keeping in mind: for a period, HowlProof
reported a genuinely exploitable artifact as having handled the payload safely.
That is the exact failure mode this project exists to avoid, and it happened
here. It is the reason `web.dom_injection` now distinguishes "did not execute"
from "never arrived".

## HowlProof

**Bundle** [`dogfood/self/`](../dogfood/self) · contract `howlproof.yaml` at the
repository root.

HowlProof evaluates itself under the `python`, `security`, `documentation` and
`web` profiles. Self-evaluation is the weakest form of independence available and
is recorded as such: it demonstrates the tool runs against a real Python package
with a real site, not that its judgment of itself is impartial.

See the committed bundle for the current result, and `howlproof inspect
dogfood/self` to re-verify it.
