# Research claims (`research.claims`)

HowlProof can evaluate a **claim bundle**: a directory holding `claims.json`
(`howl.claim_bundle/v1`) and the evidence files it names. HowlDream's
`howldream export-proof` writes one; anything else may too.

```bash
howlproof evaluate <bundle> --profile research --evidence-root <outside-the-bundle> --json
```

Everything in a bundle is untrusted data. The evaluator never executes evidence,
follows instructions found in it, or reaches the network. Instruction-like text is
recorded in `untrusted_flags` and changes no status.

## Contract

| Field | Meaning |
| --- | --- |
| `schema` | exactly `howl.claim_bundle/v1` |
| `candidate` | identity of the source candidate (`candidate_id`, `source_run_id`, ...) |
| `authorship` | `EXTERNAL_AUTHORED`, `MODEL_GENERATED`, `MOCK`, `SYNTHETIC_FIXTURE` or `UNKNOWN` |
| `claims[]` | `claim_id`, `text`, `category`, `assumption`, `evidence_refs`, optional `check`, `falsification`, `verification_plan` |
| `evidence[]` | `id`, relative `path`, `sha256`, `source_type`, `independent`, `published_at` |
| `lineage` | exporter, version, candidate digest |

An evidence file is a JSON object `{"id", "text", "facts"}`; `facts` maps a name to a
string such as `"92%"`, `"$50 per month"` or `"73.1 s"`.

## Categories

| Category | Can reach SUPPORTED/REFUTED? |
| --- | --- |
| `EMPIRICAL` | yes, through a `fact_compare` check against independent evidence |
| `TECHNICAL` | yes, through `fact_compare` or a deterministic `arithmetic` check |
| `HYPOTHESIS` (and any `assumption`) | never; always INCONCLUSIVE |
| `VALUE_JUDGMENT` (judgments, forecasts) | never; REQUIRES_EXTERNAL_VALIDATION |

## Checks (author-grounded; never invented)

* `fact_compare`: `{fact, op, expected, tolerance}`, `op` in `eq approx lt le gt ge`.
  Quantities carry units and currency; `50%` is never compared with `$50`, and a
  mismatch is INCONCLUSIVE with the reason.
* `arithmetic`: a closed grammar of numbers and `+ - * / **`. No names or calls.
  It shows internal consistency only, so it can settle a TECHNICAL claim and nothing else.
* Any other `type` is reported as an unavailable evaluator, never as success.

A claim with no check, or a citation with no check, is INCONCLUSIVE: a quotation
matching a source is not proof the source is right. A `verification_plan` is
`PROPOSED` and is never evaluated.

## Claim status and the existing result model

| Claim status | HowlProof check status | Finding |
| --- | --- | --- |
| `SUPPORTED` | `VERIFIED` | none |
| `REFUTED` | `FAILED` | HIGH `correctness` |
| `INCONCLUSIVE` | `UNAVAILABLE` (reason says why) | none |
| `REQUIRES_EXTERNAL_VALIDATION` | `SKIPPED` | none |
| `ERROR` (malformed check) | `ERROR` | none |

`SUPPORTED` needs: a grounded check, evidence whose bytes still match their `sha256`,
`independent: true` on that evidence, and no independent contradicting evidence.
Conflicting independent evidence is recorded in `conflicts` and stays INCONCLUSIVE; a
newer source is reported (`newer`) but does not resolve it.

One check per claim (`research.claims.c001`, ...) carries the full per-claim record in
`detail`. `research.claims.bundle` covers structure and evidence integrity only and says
so; passing it verifies no claim. A bundle with no claims is UNAVAILABLE, not VERIFIED.

The overall verdict still comes from the operator's acceptance contract. With none,
the verdict is `INSUFFICIENT_EVIDENCE`; the bridge never writes acceptance criteria.

## What it does not establish

Independence is as declared in the bundle and is not authenticated. A matching fact
does not show the source is correct, current or representative. Reachability of a URL
is not checked at all. Compound claims must be split by the author.
