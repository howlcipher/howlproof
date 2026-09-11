# The HowlProof contract

**HowlProof judges. It does not repair the artifact it is judging.**

Everything else in this document follows from that sentence.

## What HowlProof owns

- Inspecting an artifact's source, configuration, documentation and published interface
- Executing the artifact's own gates, and generating adversarial inputs of its own
- Defensive security analysis within an authorised, operator-owned scope
- Reliability analysis: restart, corruption, truncation, repetition
- Comparing what the documentation claims with what the implementation does
- Attempting falsification, and recording a reproduction when a defect is observed
- Producing machine-readable and human-readable evidence
- Recommending remediation, and re-evaluating independently once it has happened
- Issuing a verdict, and blocking on the evidence when the verdict justifies it

## What HowlProof does not own

| Not owned | Whose it is |
| --- | --- |
| Repairing the artifact | The artifact's builder, routed by HowlPlane |
| Deciding what gets built and by whom | HowlPlane |
| Executing, promoting or rolling back change | HowlChangeOps |
| Continuous security posture and threat intelligence | A future HowlGuard, deliberately not built here |
| Carrying work state between sessions | HowlRelay |
| Rendering work and evidence for an operator | HowlBoard |
| Being a general oracle of fact | Nothing in this ecosystem |

## How the separation is enforced

Documentation is not a control. Three mechanisms make the boundary real.

**Evaluators cannot write to the artifact.** `Target.prepare` materialises the
artifact into a workspace copy and every command runs with its working directory
inside that copy. The `Target` handle exposes `read_text`, `read_bytes`,
`iter_files`, `glob` and `run`, and nothing that writes.

**The artifact is digested before and after.** The file set is discovered and
hashed at the start, re-discovered and re-hashed at the end. Any modification,
addition or removal raises a `BLOCKER` integrity finding, forces the verdict to
`INSUFFICIENT_EVIDENCE`, and exits `4`. The reasoning is not punitive: evidence
gathered while the subject was changing does not support a conclusion about the
subject.

**Evidence is written outside the artifact.** `--evidence-root` defaults to
`./proof` relative to the working directory, and writing inside the target is
refused unless `--allow-evidence-in-target` is given.

`tests/test_evaluators.py` registers an evaluator that writes into its target and
asserts the evaluation is invalidated. If the guard regresses, that test fails.

## The remediation route

```
HowlProof evaluates
      │
      ├─ finding + reproduction + evidence bundle
      ▼
HowlPlane decides            ← ai.review_finding/v1 via `reconcile --findings-file`
      │
      ▼
the appropriate builder repairs the artifact, in the artifact's own repository
      │
      ▼
HowlProof re-evaluates       ← `howlproof verify-fix`
      │
      ▼
VERIFIED_FIXED, or still RETESTED
```

The loop has one rule that everything else protects: **a statement that a defect
was fixed is not evidence that it was.** `verify-fix` refuses to answer when the
artifact's tree digest matches the state the finding was raised against, and when
the artifact has changed it re-runs the evaluator that raised the finding rather
than replaying a claim. If that evaluator could not run against the changed
artifact, the finding's absence is reported as inconclusive, not as a fix.

## What a verdict means

A verdict is a statement about the evidence, not about the artifact in general.

`PROVEN` says three things at once: every acceptance criterion was satisfied, no
unresolved finding sits at or above the blocking severity, and enough checks
actually produced a conclusive result to justify the conclusion. Remove any one
of those and the verdict weakens.

`INSUFFICIENT_EVIDENCE` exists because the alternative is worse. An evaluation
where the required tooling was missing, where a criterion rested on a check that
never ran, or where coverage fell below the declared floor has not shown the
artifact is bad. It has also not shown it is good, and saying so is the only
honest option.

The derivation is ordered, deterministic, and recorded. `howlproof explain` prints
the rule that fired and the criteria table that produced it, so the conclusion can
be disagreed with rather than merely accepted.

## What HowlProof will not become

It will not gain the ability to repair. A component that can both condemn and fix
has an incentive to condemn what it can fix and overlook what it cannot, and its
verdicts stop being independent evidence. The separation is the product.
