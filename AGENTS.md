# HowlProof engineering guidance

Read README.md, docs/contract.md and docs/ecosystem.md before changing an
evaluator. HowlProof judges; it does not repair the artifact it is judging. No
evaluator may write to the target, and the tree-digest guard in target.py exists
to catch it if one tries.

A check that cannot run must say so. UNAVAILABLE, SKIPPED, NOT_APPLICABLE and
ERROR each require a reason, and every check must state what it does not
establish. Never widen a status to make a result look better than the evidence.

New behavior needs a failing contract test before implementation. Evaluators need
a fixture carrying the defect they look for and a clean fixture they must stay
quiet on. Do not weaken a test to make a run green.

Run the README verification commands. Use conventional commits and update
README.md and change_log.md before committing. Committed dogfood bundles are
historical evidence: write a new evaluation rather than editing an old one.
