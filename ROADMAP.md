# Roadmap

## Milestone 1: The adversary exists

Strict evaluation contracts, typed acceptance criteria, twenty-eight evaluators
across five adversaries, the six-value check vocabulary, the five verdicts,
evidence bundles with an integrity index, the finding ledger and durable
identifiers, the falsification loop through `verify-fix`, documented file
contracts into HowlPlane, HowlBoard and HowlRelay, and dogfood evaluations of a
real ecosystem component and of HowlProof itself. Experimental, not
production-ready.

## Milestone 2: Depth over breadth

The current checks are wide and shallow in places. The next work is to make a
smaller number of them genuinely hard to pass.

- Turn `markup.escaping` from a single-context analysis into a small dataflow
  pass, so a value's path from source to sink is traced rather than pattern
  matched within a window.
- Replace the fixed `ai.promptinjection` corpus with a measured suite carrying a
  labelled baseline, so a clean result means something quantitative rather than
  "these five strings did not work".
- Concurrency as a first-class adversary: parallel mutating requests against a
  declared endpoint, checking for lost updates and colliding identifiers.
- Real fault injection through a local proxy for artifacts that declare an
  upstream dependency, which today is the largest gap the `SIMULATED` label
  covers for.

## Milestone 3: Evidence that travels

- A signed evidence bundle, so a verdict can be trusted after it leaves the
  machine that produced it. Today the integrity index proves a bundle has not
  been edited in place; it does not prove who produced it.
- Native ingestion, if and only if operational use shows the file contracts are
  insufficient. HowlPlane's control-plane architecture is frozen, so any proposal
  here must carry the operational evidence that freeze requires.
- Cross-artifact regression: replaying every `VERIFIED_FIXED` reproduction across
  the ecosystem on a schedule, so a fix that quietly regresses in a sibling is
  caught.

## Milestone 4: Calibration

The verdict model is currently argued for, not measured. This milestone asks
whether it is any good.

- A labelled corpus of artifacts with known defects, so false-negative and
  false-positive rates per evaluator can be stated as numbers.
- Agreement between HowlProof verdicts and later real-world outcomes, which is
  the only honest way to find out whether `CONDITIONALLY_PROVEN` carries the
  meaning this milestone assigns it.
- Until that exists, no claim about detection rate belongs in the documentation.

## Explicitly not planned

**HowlGuard.** Continuous security posture intelligence is a different question
from independent evaluation of one artifact, and merging them would give the
evaluator a standing opinion about the thing it is supposed to judge freshly.
The boundary is written down in `docs/ecosystem.md`; the component is not built
here.

**Autonomous repair.** HowlProof will not gain the ability to fix what it finds.
The separation is the product.
