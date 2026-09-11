# Ecosystem boundaries and handoffs

Inspected 11 September 2026: HowlPlane's control-plane documentation, schemas and
CLI; HowlChangeOps' adapter and policy; HowlRelay's models and collectors;
HowlBoard's domain model and import tool; the Howl hub's site and manifest.

## Where HowlProof sits

| Component | Its role | Relationship to HowlProof |
| --- | --- | --- |
| HowlDream | Speculative experiments and scoped verification of generated claims | Neither evaluates the other; Dream challenges ideas, Proof challenges artifacts |
| HowlCreate | Intentional invention and concept lineage | Upstream of anything Proof would evaluate |
| HowlPlane | Orchestration, routing, independent review, authority gates | Consumes Proof findings as advisory evidence and decides what to do about them |
| HowlFrame | Language, compiler and capability-bounded VM | An artifact Proof can evaluate, not a dependency of it |
| HowlChangeOps | Governed change execution, approvals, rollback | Owns promotion. Proof produces the evidence; ChangeOps decides |
| HowlRelay | Async work state and handoff | Can carry a Proof verdict and its unresolved risks into the next session |
| HowlBoard | Mission and evidence rendering | Can render Proof evidence once it has flowed through HowlPlane's ledger |
| HowlWriter | Writing, citation and provenance | Unrelated surface; would be an artifact, not an integration |
| Howl | Installer and canonical Pages hub | Proof is not in the default installer manifest |

## Why the integrations are files

HowlPlane's control-plane architecture is explicitly frozen: new framework
capabilities are forbidden unless real operational use exposes a defect. Adding a
HowlProof-shaped API to it would be exactly the kind of speculative feature that
freeze exists to refuse.

So HowlProof emits files in schemas the ecosystem already reads. No sibling
component changes, and each contract is a documented file format rather than a
claim of native API compatibility.

### HowlPlane

`howlproof handoff <bundle> --for plane` writes `ai.review_finding/v1` YAML for
`python -m src.control_plane reconcile --findings-file <file>`, which is the
documented ingest point for externally produced findings.

Severity maps directly, because HowlProof deliberately adopted HowlPlane's
vocabulary (`blocker`, `high`, `medium`, `low`, `informational`) rather than
inventing `CRITICAL`/`INFO` and then translating. Lifecycle state maps to review
status:

| HowlProof state | `ai.review_finding/v1` status |
| --- | --- |
| `FOUND` | `open` |
| `REPRODUCED`, `REMEDIATION_REQUESTED`, `RETESTED`, `VERIFIED_FIXED`, `REGRESSED` | `confirmed` |
| `NOT_REPRODUCED` | `likely` |
| `ACCEPTED_RISK`, `WONT_FIX` | `out_of_scope`, with the resolution reason attached |

HowlProof enforces HowlPlane's anti-silent-dismissal rule at its own boundary: a
finding at `BLOCKER` or `HIGH` cannot be constructed in a dismissed state without
a non-empty reason.

`--for verification-plan` writes `ai.verification_plan/v1`. That schema's status
enum has no value meaning "the tool was not installed", so `UNAVAILABLE`,
`NOT_APPLICABLE` and `ERROR` all map to `skipped` and the original status is
preserved in each step's notes. The mapping is lossy and the document says so.

### HowlBoard

`--for board` writes `ai.evidence_entry/v1` JSONL, the same format HowlPlane's
evidence ledger holds and HowlBoard's `ledger_import` projects into missions.
HowlBoard has no API to append verification records to an existing mission, so
this is the supported route.

HowlBoard's domain model is explicit that a new value judgment must be defined
upstream before Board renders it. HowlProof's verdicts therefore live in the
`howlproof.*` namespace and are carried into Board's vocabulary through the
evidence entry's `result` and `defect_type` fields rather than introducing new
strings Board would not recognise.

### HowlRelay

`--for relay` writes markdown under the headings HowlRelay's continuity collector
recognises: `Objective`, `Current State`, `Known Failures`, `Blockers`,
`Next Recommended Action`, `Commands to Resume Work`. It carries no per-person
measurement of any kind, which is what HowlRelay's surveillance-signal policy
requires of anything contributing to its state.

### HowlChangeOps

**There is no ingest path, and the handoff says so.**

HowlChangeOps gathers its own evidence and projects exactly two of its check
results, `test` and `build`, into its HowlFrame policy. There is no parameter
through which an external verdict reaches a gate. `--for changeops` therefore
writes a human-readable advisory that states this plainly instead of implying a
machine contract exists.

The supported way to make a HowlProof verdict affect promotion is to raise it in
HowlPlane, which already owns the boundary that gates package publishing.

## HowlProof and HowlChangeOps are not the same component

They are adjacent and easily confused, so the line is worth stating.

| | HowlProof | HowlChangeOps |
| --- | --- | --- |
| Question | Can I demonstrate this artifact should not be trusted? | Is this change authorised to happen, and can it be undone? |
| Output | Evidence and a verdict | A decision, an execution receipt, a rollback path |
| Authority | None. Advisory only | The release boundary |
| Timing | Before promotion, and again after remediation | At promotion |
| Failure mode it prevents | Believing something was verified when it was not | Something happening that nobody authorised |

A ChangeOps approval over an unverified artifact is a governed mistake. A
HowlProof `PROVEN` verdict with no ChangeOps gate is an ungoverned success.
Both components are needed and neither substitutes for the other.

## The HowlGuard boundary, documented and not built

A future HowlGuard would ask a different question:

> **HowlProof:** Can I demonstrate that this artifact should not be trusted?
>
> **HowlGuard:** Has the ecosystem's security posture changed in a way that
> requires new evaluation?

Proof is episodic and artifact-scoped: it is pointed at one thing, at one commit,
and answers about that. Guard would be continuous and ecosystem-scoped: watching
advisories, dependency drift and configuration change, and deciding when
something needs looking at again.

They are deliberately not the same component. An evaluator that also maintains a
standing opinion about its subject stops evaluating it freshly. HowlProof is
architected so a Guard could drive it — evaluations are configuration-driven,
profiles are data, evidence bundles are addressable and comparable, and the
finding ledger already answers "have we seen this before" — without Guard's
concerns leaking into the evaluator.

Nothing of HowlGuard is implemented. This section is a boundary, not a plan.

## Installer status

**Not included in the default Howl installer manifest.** HowlProof is
experimental, milestone one, and the installer's manifest describes tested,
supported components. Inclusion is a decision for the hub, not a claim this
repository makes on its own behalf.
