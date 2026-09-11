# HowlProof result

HowlProof judges. It does not repair the artifact it is judging.

Artifact: howlboard
Commit: 82358ffd18b4e74532c86a24e04988428a10dc26
Branch: fix/escape-mission-id-for-handler-context
Run: hp-20260911-135257-e7c81bc63b96
Profiles: markup.escaping
Completed: 2026-09-11T13:52:57.421472+00:00

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

0 verified, 1 failed, 0 skipped, 0 unavailable, 0 not applicable, 0 errored.

| Check | Checker | Status | Mode | Note |
| --- | --- | --- | --- | --- |
| markup.escaping | markup.escaping/v1 | FAILED | REAL | 1 interpolations are escaped inadequately for their context |

## Validation modes

- **REAL**: markup.escaping
- **SIMULATED**: none
- **SKIPPED**: none
- **UNAVAILABLE**: none
- **NOT_APPLICABLE**: none
- **ERROR**: none

## Findings

### HP-SEC-0005 — `set_html` builds markup from an interpolated value in frontend/app.howl

- Adversary: SECURITY
- Category: security
- Severity: MEDIUM
- Confidence: HIGH
- State: FOUND
- Blocking: no
- Location: frontend/app.howl:201

A call to `set_html` assembles HTML containing an interpolated value and no escape function appears in the surrounding expression.

Evidence:

```
set_html (dom_query "#feed") (str_join (list html "</div>") ""))
          )
        )
      )
    )
  )

  (defun open_mission (id)
    (type_hint return "void")
    (try_let (raw (fetch (call api_url "/api/missions/get") "POST" (str_join (list "{\"id\":\"" id "\"}") "")))
      (catch err (call sh
```

Recommended remediation (for the artifact's owner, not for HowlProof): Route every interpolated value through the artifact's escape function, or set text content instead of markup.

Reproduction: Re-read the source and match the same construction.

1. Inspect frontend/app.howl around line 201.


## Unresolved risks

- HP-SEC-0005 (MEDIUM): A call to `set_html` assembles HTML containing an interpolated value and no escape function appears in the surrounding expression.

## Limitations

No skipped, unavailable or simulated checks in this run.

--------------------------------------------------------------------

This report is advisory evidence. HowlProof does not promote, merge, deploy or approve anything. Remediation belongs to the artifact's builder and promotion to HowlPlane and HowlChangeOps.
