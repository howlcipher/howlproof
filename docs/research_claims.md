# Research claims (`research.claims`)

HowlProof can evaluate a **claim bundle**: a directory holding `claims.json`
(`howl.claim_bundle/v1`) and the evidence files it names. HowlDream's
`howldream export-proof` writes one; anything else may too.

```bash
howlproof evaluate <bundle> --profile research --evidence-root <outside-the-bundle> --json
```

Everything in a bundle is untrusted data. The evaluator never executes evidence,
follows instructions found in it, or reaches the network. Instruction-like text, in an
evidence record or in an acquired source, is recorded in `untrusted_flags` and changes no
status. Retrieval is a separate, explicit command (`howlproof acquire`), never part of
`evaluate`.

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
* `text_presence`: `{term, expect: present|absent}` over the cited artifact(s) only. The
  result is always `scope_limited`: a term missing from one document is never reported as
  the feature missing from the project, `also_found_in` lists other bundle evidence that does
  contain the term, and `broader_question` stays `NOT_EVALUATED`.
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

A bare small number (fewer than three digits, no unit, currency or scale: `0`, `1`, `9`) can
never be located in a source: it is how an agent encodes a flag or count, and it would "appear"
in almost any page. Such facts leave a sourced claim INCONCLUSIVE. `text_presence` records
`artifacts_disagree` in `conflicts` (with `newer`) when one cited artifact contains the term
and another lacks it; a source that contains the term is decisive for `expect: absent`, and
one containing it supports `expect: present`, because absence from one document is never proof.

`SUPPORTED`/`REFUTED` for a **sourced** claim (EMPIRICAL, or TECHNICAL via `fact_compare` or
`text_presence`) needs all of: a grounded check; evidence whose bytes match their `sha256`;
`independent: true` declared (necessary, never sufficient); an `acquisition` pointer that
verifies against the operator's acquisition store (`--acquisition-store`) and whose recorded
location matches the evidence's `source_ref`; the compared fact value present in the acquired
source bytes; every claim `subject_terms` entry present in that source (this is the
structural relevance check; a claim with no `subject_terms` cannot establish relevance); and,
for `nature: measurement` (the default for `fact_compare`), a `methodology_quote` of at least 25
characters and 4 words that appears in the source (a bare phrase such as the product name does
not count). `nature: reported_fact` waives only the methodology requirement and is
author-declared. Bundles declared `SYNTHETIC_FIXTURE`/`MOCK` skip the source requirements and
are reported `real_world_eligible: false`, `real_world_truth: NOT_APPLICABLE_SYNTHETIC`.
Deterministic `arithmetic` on a TECHNICAL claim stays SUPPORTED/REFUTED but reports
`evidence_status: DETERMINISTIC_CHECK_ONLY` and `input_provenance: UNVERIFIED`.

When a check agrees or disagrees with supplied numbers but the evidence cannot meet the bar,
the claim is INCONCLUSIVE, the explanation says why, and the arithmetic is preserved in
`check_outcome` (`SUPPORTED`/`REFUTED`), `evidence_status` is `SUPPLIED_DATA_AGREES` or
`SUPPLIED_DATA_CONTRADICTS`. Conflicting evidence is recorded in `conflicts` and stays
INCONCLUSIVE; a newer source is reported (`newer`) but does not resolve it.

## Trust model and the `assurance` record

Six different things are called "verified" in research. They are separate fields and are never
merged into a score:

| Dimension (`assurance.*`) | Values | Establishes | Does not establish |
| --- | --- | --- | --- |
| `check_passed` | true/false/null | the check's condition held on the data it saw | that the data is real |
| `evidence_integrity` | ok / mismatch / missing / not_applicable | stored bytes match their digest | that they were truthful when made |
| `source_origin` | NOT_EXAMINED (arithmetic, forecasts, claims with no check: their citations were never read), OBSERVED_ACQUISITION, OPERATOR_ATTESTED_FILE, SYNTHETIC_FIXTURE, UNVERIFIABLE, CLAIMED_ONLY, PLACEHOLDER, AGENT_AUTHORED, NONE | where the source bytes came from, as far as an inspectable acquisition event shows | that the source's claims are correct |
| `claim_relevance` | STRUCTURAL_MATCH, NOT_ESTABLISHED, NOT_APPLICABLE(_SYNTHETIC) | the fact and the claim's subject terms occur in the source | that the source substantively addresses the claim; a reviewer must still read it |
| `methodology` | RECORDED, NOT_REQUIRED, NOT_RECORDED, NOT_EVALUATED | a quoted methodology exists in the source | that the methodology is sound |
| `corroboration` / `corroborated` | NONE, SINGLE_SOURCE, DUPLICATES_ONLY, SEPARATE_ARTIFACTS_ORIGIN_UNASSESSED / always false | duplicate artifacts are detected | independence of origin; this milestone cannot establish it |
| `real_world_truth` | UNRESOLVED, NOT_ESTABLISHED, NOT_APPLICABLE_SYNTHETIC | nothing: it is a reminder | that the claim is true |
| `evidence_status` | SOURCE_VERIFIED(_SCOPED), DETERMINISTIC_CHECK_ONLY, SYNTHETIC_FIXTURE_ONLY, SUPPLIED_DATA_AGREES/CONTRADICTS, UNRESOLVED | a one-word summary of the above | |

Per evidence row, `claimed_provenance` holds what the bundle declared and `trust` holds what
was observed. The two are never merged.

### Evidence entry additions (all optional; `howl.claim_bundle/v1` is unchanged otherwise)

* `acquisition: {id, content_sha256}`: pointer into the acquisition store.
* `methodology_quote`: a literal excerpt of the source describing its method.

### Claim additions (all optional)

* `subject_terms: [..]`: terms the source must contain to be structurally relevant.
* `checked_proposition`: the exact proposition checked (defaults to `text`; for `text_presence`
  with none supplied, a derived statement of the artifact-level check, never the broad claim);
  echoed in the result.
* `scope: {artifact, extent}`: what the proposition covers; any `extent` other than
  `FULL_QUESTION` sets `scope_limited`. Proof never evaluates the broader question
  (`broader_question: NOT_EVALUATED`).
* check `nature`: `measurement` (default) or `reported_fact`.

## Resource bounds

At most 200 evidence entries and 500 claims per bundle; a stored artifact larger than 4 MiB is
refused (`TOO_LARGE`); retained source text across one bundle is capped at 32 M characters and
overflow is reported `SOURCE_BUDGET_EXCEEDED` (unverifiable, never silently dropped). Markup is
reduced to text in a single linear pass: a regex-based stripper took 17 s on 200 KB of `<`, so a
hostile page could stall an evaluation. Regression tests cover it.

## Known limits (asserted in `tests/test_evidence_adversarial.py`)

These attacks still succeed, by design of what can be checked mechanically: a real number with
the wrong meaning (location finds the number, not its sense); author-chosen `subject_terms` that
are too generic; a vendor's own page (a single, uncorroborated source); and a forged record by
anyone who can write the acquisition store. Each result still reports `claim_relevance:
STRUCTURAL_MATCH` (never "substantive"), `real_world_truth: UNRESOLVED` and
`corroborated: false`.

## Acquisition (`howlproof acquire`)

```bash
howlproof acquire --store STORE --url https://host/page          # opt-in retrieval
howlproof acquire --store STORE --file page.html --source-url https://host/page --operator me
howlproof evaluate bundle/ --profile research --acquisition-store STORE --evidence-root OUT
```

A record in `STORE/records/<id>.json` holds the requested and observed URL, redirects, method,
time, status, content type, size, tool version and the sha256 of the raw bytes in
`STORE/raw/`. Failures are logged to `STORE/attempts.jsonl`. Fetching is http/https only on
default ports, refuses credentials, non-global addresses (loopback, private, link-local,
metadata, CGNAT, multicast, translated/tunnelled IPv6) for every resolved address and every
redirect hop, pins the connection to the validated address, caps redirects (3), time (10 s) and
size (2 MiB), keeps only inert text content types, and never interprets what it stores.

The store is the trust anchor: it must live outside the bundle and be written only by the
operator. Records carry a self-digest so edited records or swapped bytes are detected. That is
tamper *evidence*, not authentication: whoever can write the store can forge a record. There is
no signing key or execution boundary, so none is claimed. `OPERATOR_FILE` records are
attested, not observed, and are labelled `OPERATOR_ATTESTED_FILE`.

## Compatibility and migration

* `howl.claim_bundle/v1` is unchanged; new fields are optional. Verdict names are unchanged.
* **SUPPORTED/REFUTED semantics for sourced claims are stricter.** A pre-M2 bundle (no
  `acquisition`, no `subject_terms`) re-evaluated now reports INCONCLUSIVE for its empirical
  claims, with `check_outcome` holding what the old evaluator would have said. Historical
  results are not rewritten; evaluate again to get an M2 result.
* Deterministic TECHNICAL arithmetic and VALUE_JUDGMENT/HYPOTHESIS handling are unchanged.
* New result keys (`assurance`, `check_outcome`, `check_passed`, `checked_proposition`,
  `scope`, `scope_limited`, `broader_question`, `also_found_in` (only artifacts that contain
  every `subject_term`), per-row `trust`,
  `claimed_provenance`, `eligible`, `ineligible_reasons`) are additive.

One check per claim (`research.claims.c001`, ...) carries the full per-claim record in
`detail`. `research.claims.bundle` covers structure and evidence integrity only and says
so; passing it verifies no claim. A bundle with no claims is UNAVAILABLE, not VERIFIED.

The overall verdict still comes from the operator's acceptance contract. With none,
the verdict is `INSUFFICIENT_EVIDENCE`; the bridge never writes acceptance criteria.

## What it does not establish

Independence of origin is never established (`corroborated` stays false); duplicates are
detected, distinct artifacts are merely recorded. A located fact does not show the source is
correct, current or representative, and structural relevance (terms present) is not
substantive relevance. `subject_terms`, `nature` and `scope` are author-declared. The
acquisition store is not authenticated against a determined forger with write access. A
vendor's own page can pass every check yet still be a single, self-interested source.
`evaluate` never fetches. Compound claims must be split by the author.
