# HowlProof result

HowlProof judges. It does not repair the artifact it is judging.

Artifact: howlboard
Commit: 82358ffd18b4e74532c86a24e04988428a10dc26
Branch: fix/escape-mission-id-for-handler-context
Run: hp-20260911-135058-acbea8a02413
Profiles: web.dom_injection
Completed: 2026-09-11T13:51:10.904490+00:00

## Verdict: INSUFFICIENT_EVIDENCE

The artifact may or may not be acceptable. The evaluation that ran was inadequate to make a defensible determination, so no determination is claimed.

Deciding rule: `no_acceptance_criteria`

- The artifact defines no acceptance criteria.
- Running checks without criteria shows activity, not conformance.

## Acceptance criteria

0 of 0 satisfied.

| Criterion | Requirement | Outcome | Detail |
| --- | --- | --- | --- |

## Checks

1 verified, 0 failed, 0 skipped, 0 unavailable, 0 not applicable, 0 errored.

| Check | Checker | Status | Mode | Note |
| --- | --- | --- | --- | --- |
| web.dom_injection.mission_id_js_string | web.dom_injection/v1 | VERIFIED | REAL | mission_id_js_string: the payload reached the page and was rendered as data rather than executed |

## Validation modes

- **REAL**: web.dom_injection.mission_id_js_string
- **SIMULATED**: none
- **SKIPPED**: none
- **UNAVAILABLE**: none
- **NOT_APPLICABLE**: none
- **ERROR**: none

## Findings

No findings were raised by the checks that ran.

## Unresolved risks

None recorded.

## Limitations

No skipped, unavailable or simulated checks in this run.

--------------------------------------------------------------------

This report is advisory evidence. HowlProof does not promote, merge, deploy or approve anything. Remediation belongs to the artifact's builder and promotion to HowlPlane and HowlChangeOps.
