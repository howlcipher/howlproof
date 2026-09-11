# HowlProof result

HowlProof judges. It does not repair the artifact it is judging.

Artifact: howlboard
Commit: 56246a9b47b0fe0b829756069fa70764a42c7213
Branch: chore/ecosystem-drawer-sync-howldream
Run: hp-20260911-133826-ddbaef4e94e2
Profiles: security, api, web, documentation, reliability
Completed: 2026-09-11T13:39:22.536130+00:00

## Verdict: REJECT

Evidence demonstrates that the artifact violates acceptance criteria, security or reliability requirements, policy, or another blocking condition.

Deciding rule: `blocking_evidence`

- AC-01 violated: 2 security findings at or above HIGH, limit 0
- HP-SEC-0007 (HIGH, reproduction confirmed): Stored data executes as script in the interface: mission_id_js_string

## Acceptance criteria

6 of 7 satisfied.

| Criterion | Requirement | Outcome | Detail |
| --- | --- | --- | --- |
| AC-01 | max_findings | VIOLATED | 2 security findings at or above HIGH, limit 0 |
| AC-02 | checks_pass | SATISFIED | 2 required checks verified |
| AC-03 | checks_pass | SATISFIED | 2 required checks verified |
| AC-04 | checks_pass | SATISFIED | 2 required checks verified |
| AC-05 | tool_required | SATISFIED | 1 required tools present |
| AC-06 | no_regressions | SATISFIED | no previously fixed finding reappeared |
| AC-07 | coverage_floor | SATISFIED | 16 of 17 applicable checks were conclusive (0.94), floor 0.60 |

## Checks

12 verified, 4 failed, 0 skipped, 1 unavailable, 3 not applicable, 0 errored.

| Check | Checker | Status | Mode | Note |
| --- | --- | --- | --- | --- |
| secrets.scan | secrets.scan/v1 | VERIFIED | REAL | no credential-shaped strings in 29 text files |
| ci.supplychain | ci.supplychain/v1 | FAILED | REAL | 4 supply-chain weaknesses across 1 workflows |
| markup.escaping | markup.escaping/v1 | FAILED | REAL | 2 interpolations are escaped inadequately for their context |
| sast.bandit | sast.bandit/v1 | UNAVAILABLE | REAL | the artifact has no pyproject.toml to install |
| deps.audit | deps.audit/v1 | NOT_APPLICABLE | REAL | the artifact declares no Python dependencies to audit |
| http.authz.execute_without_approval | http.authz/v1 | VERIFIED | REAL | execute_without_approval: refused with 403 as documented |
| http.authz.execute_with_expired_approval | http.authz/v1 | VERIFIED | REAL | execute_with_expired_approval: refused with 403 as documented |
| web.dom_injection.mission_id_js_string | web.dom_injection/v1 | FAILED | REAL | mission_id_js_string: the payload executed in the browser |
| http.abuse | http.abuse/v1 | VERIFIED | REAL | 7 malformed requests were rejected cleanly and the service stayed up |
| api.idempotency | api.idempotency/v1 | VERIFIED | REAL | repeating the request returned 201; responses differed, which a create endpoint may intend |
| reliability.partial_request | reliability.partial_request/v1 | VERIFIED | REAL | the service survived truncated and invalid connections |
| web.links | web.links/v1 | VERIFIED | REAL | all 50 references resolve |
| web.metadata | web.metadata/v1 | VERIFIED | REAL | 1 pages carry title, description, canonical, Open Graph tags and a single h1, alongside robots.txt and sitemap.xml |
| web.responsive | web.responsive/v1 | FAILED | REAL | 1 rendering problems across 3 widths |
| docs.claims.absolutes | docs.claims/v1 | VERIFIED | REAL | 18 absolute documentation claims collected for challenge |
| docs.claims.sync | docs.claims/v1 | VERIFIED | REAL | all 1 file pairs documented as synchronised are identical |
| cli.destructive | cli.destructive/v1 | NOT_APPLICABLE | REAL | the artifact declares no destructive subcommands to inspect |
| release.version | release.version/v1 | NOT_APPLICABLE | REAL | the artifact has no pyproject.toml declaring a version |
| service.restart | service.restart/v1 | VERIFIED | REAL | the service restarted and answered again; state survived the restart |
| reliability.corrupt_store | reliability.corrupt_store/v1 | VERIFIED | SIMULATED | with howlboard_missions.json truncated the artifact refused to start with a diagnostic |

## Validation modes

- **REAL**: secrets.scan, ci.supplychain, markup.escaping, http.authz.execute_without_approval, http.authz.execute_with_expired_approval, web.dom_injection.mission_id_js_string, http.abuse, api.idempotency, reliability.partial_request, web.links, web.metadata, web.responsive, docs.claims.absolutes, docs.claims.sync, service.restart
- **SIMULATED**: reliability.corrupt_store
- **SKIPPED**: none
- **UNAVAILABLE**: sast.bandit
- **NOT_APPLICABLE**: deps.audit, cli.destructive, release.version
- **ERROR**: none

## Findings

### HP-SEC-0001 — actions/checkout is pinned to a mutable reference

- Adversary: SECURITY
- Category: security
- Severity: MEDIUM
- Confidence: HIGH
- State: FOUND
- Blocking: no
- Location: .github/workflows/ci.yml:15

.github/workflows/ci.yml runs actions/checkout at `v4`, a tag or branch the action's owner can repoint at any time. A compromised or retagged action executes with this workflow's token.

Evidence:

```
uses: actions/checkout@v4
```

Recommended remediation (for the artifact's owner, not for HowlProof): Pin the action to a full 40-character commit SHA and record the intended version in a comment.

Reproduction: Re-read the workflow and match the same construct.

1. Inspect .github/workflows/ci.yml at line 15.

### HP-SEC-0002 — actions/setup-go is pinned to a mutable reference

- Adversary: SECURITY
- Category: security
- Severity: MEDIUM
- Confidence: HIGH
- State: FOUND
- Blocking: no
- Location: .github/workflows/ci.yml:18

.github/workflows/ci.yml runs actions/setup-go at `v5`, a tag or branch the action's owner can repoint at any time. A compromised or retagged action executes with this workflow's token.

Evidence:

```
uses: actions/setup-go@v5
```

Recommended remediation (for the artifact's owner, not for HowlProof): Pin the action to a full 40-character commit SHA and record the intended version in a comment.

Reproduction: Re-read the workflow and match the same construct.

1. Inspect .github/workflows/ci.yml at line 18.

### HP-SEC-0003 — actions/setup-python is pinned to a mutable reference

- Adversary: SECURITY
- Category: security
- Severity: MEDIUM
- Confidence: HIGH
- State: FOUND
- Blocking: no
- Location: .github/workflows/ci.yml:23

.github/workflows/ci.yml runs actions/setup-python at `v5`, a tag or branch the action's owner can repoint at any time. A compromised or retagged action executes with this workflow's token.

Evidence:

```
uses: actions/setup-python@v5
```

Recommended remediation (for the artifact's owner, not for HowlProof): Pin the action to a full 40-character commit SHA and record the intended version in a comment.

Reproduction: Re-read the workflow and match the same construct.

1. Inspect .github/workflows/ci.yml at line 23.

### HP-SEC-0004 — .github/workflows/ci.yml declares no GITHUB_TOKEN permissions

- Adversary: SECURITY
- Category: security
- Severity: MEDIUM
- Confidence: HIGH
- State: FOUND
- Blocking: no
- Location: .github/workflows/ci.yml:1

Without an explicit `permissions:` block the workflow inherits the repository default, which may grant write access to contents, packages and more than the job needs.

Evidence:

```
no top-level or per-job `permissions:` key
```

Recommended remediation (for the artifact's owner, not for HowlProof): Add `permissions: {contents: read}` and widen only where required.

Reproduction: Re-read the workflow and match the same construct.

1. Inspect .github/workflows/ci.yml at line 1.

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

### HP-SEC-0006 — `esc` does not escape the single quote but is used inside a JavaScript string literal

- Adversary: SECURITY
- Category: security
- Severity: HIGH
- Confidence: HIGH
- State: FOUND
- Blocking: no
- Location: frontend/mission_view.howl:134

`esc` escapes ", &, <, > and not the single quote (defined at frontend/mission_view.howl:64). At frontend/mission_view.howl:134 its output is placed inside a single-quoted JavaScript string in an event-handler attribute. The HTML parser decodes the attribute before JavaScript parses it, so a single quote in the value terminates the string literal and everything after it becomes code. Escaping the double quote prevents breaking out of the attribute; it does not prevent breaking out of the string.

Evidence:

```
tton type=\"button\" class=\"mission-row s-" (call esc st) "\""
              " onclick=\"window.open_mission('" (call esc id) "')\">") ""))
```

Recommended remediation (for the artifact's owner, not for HowlProof): Escape the single quote in the escape function, or stop embedding values in handler attributes and bind the listener in code instead. Escaping for HTML text is not sufficient for a JavaScript context.

Reproduction: Re-read the source and match the same construction.

1. Inspect frontend/mission_view.howl around line 134.

### HP-SEC-0007 — Stored data executes as script in the interface: mission_id_js_string

- Adversary: SECURITY
- Category: security
- Severity: HIGH
- Confidence: CONFIRMED
- State: FOUND
- Blocking: yes
- Location: frontend/index.html

A mission identifier carrying a single quote, placed in the fixture the seed endpoint loads. Identifiers created through the API are server assigned, but seeded and ledger-imported records keep whatever identifier the source document carried.. A value placed at /missions/0/id in data/fixtures/missions.json and loaded through the artifact's own seed path set `window.__howlproof_injection` when the interface rendered it, which means the value was parsed as code rather than displayed as text.

Evidence:

```
{
  "payload": {
    "name": "mission_id_js_string",
    "file": "data/fixtures/missions.json",
    "pointer": "/missions/0/id",
    "value": "HF-412'); window.__howlproof_injection=1; ('",
    "description": "A mission identifier carrying a single quote, placed in the fixture the seed endpoint loads. Identifiers created through the API are server assigned, but seeded and ledger-imported records keep whatever identifier the source document carried."
  },
  "seed": {
    "status": 200,
    "elapsed_ms": 7,
    "headers": {
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Origin": "*",
      "Content-Type": "application/json",
      "Date": "Fri, 11 Sep 2026 13:38:26 GMT",
      "Content-Length": "33",
      "Connection": "close"
    },
    "body": "{\"missions\":5,\"status\":\"seeded\"}\n",
    "error": ""
  },
  "marker_set": true,
  "payload_reached_the_page": true,
  "console": []
}
```

Recommended remediation (for the artifact's owner, not for HowlProof): Escape for the context the value lands in, or stop placing data inside executable attributes. Remediation belongs to the artifact's builder; HowlProof only reports and re-verifies.

Reproduction: Write the payload into the seed file, seed the running service, load index.html and read window.__howlproof_injection.

1. Set /missions/0/id in data/fixtures/missions.json to the authored payload
2. POST /api/seed
3. Load frontend/index.html in a browser and read window.__howlproof_injection

### HP-OPS-0001 — The published site fails rendered checks at declared widths

- Adversary: OPERATOR
- Category: other
- Severity: MEDIUM
- Confidence: CONFIRMED
- State: FOUND
- Blocking: no
- Location: not localised

index.html@375: the document scrolls horizontally

Evidence:

```
[
  {
    "page": "index.html",
    "width": 375,
    "why": "the document scrolls horizontally"
  }
]
```

Recommended remediation (for the artifact's owner, not for HowlProof): Correct the layout or markup so each width renders without these defects.

Reproduction: Re-run web.responsive against the artifact.

1. Render the declared pages again at each declared width.

### HP-OPS-0002 — 18 absolute documentation claims are unverified

- Adversary: OPERATOR
- Category: other
- Severity: INFORMATIONAL
- Confidence: CONFIRMED
- State: FOUND
- Blocking: no
- Location: not localised

The documentation asserts these without qualification. Each one is a promise a single counterexample breaks, and this evaluation did not independently establish any of them: README.md:17 JavaScript backend. There is no hand-written server code and no hand-written; README.md:27 - **Authority is derived on every read, never replayed from storage.** An; README.md:29 once it lapses, and a mission cannot enter `EXECUTING` without live delegated; README.md:33 its own status with an explicit note, never folded into `passed`.; README.md:34 - **Demo data is labelled.** Every record carries `provenance`. Hand-authored; README.md:84 the mission lifecycle, every invalid state transition, authority expiry,

Evidence:

```
[
  {
    "file": "README.md",
    "line": 17,
    "claim": "JavaScript backend. There is no hand-written server code and no hand-written"
  },
  {
    "file": "README.md",
    "line": 27,
    "claim": "- **Authority is derived on every read, never replayed from storage.** An"
  },
  {
    "file": "README.md",
    "line": 29,
    "claim": "once it lapses, and a mission cannot enter `EXECUTING` without live delegated"
  },
  {
    "file": "README.md",
    "line": 33,
    "claim": "its own status with an explicit note, never folded into `passed`."
  },
  {
    "file": "README.md",
    "line": 34,
    "claim": "- **Demo data is labelled.** Every record carries `provenance`. Hand-authored"
  },
  {
    "file": "README.md",
    "line": 84,
    "claim": "the mission lifecycle, every invalid state transition, authority expiry,"
  },
  {
    "file": "README.md",
    "line": 136,
    "claim": "- [Domain model](docs/domain_model.md) \u2014 every field mapped to its ecosystem source"
  },
  {
    "file": "docs/architecture.md",
    "line": 38,
    "claim": "through the same module as the product is the reason it cannot drift from it \u2014"
  },
  {
    "file": "docs/architecture.md",
    "line": 41,
    "claim": "**Authority is computed, not stored.** `envelope_status` runs on every read and"
  },
  {
    "file": "docs/architecture.md",
    "line": 45,
    "claim": "prevent. The cost is that authority cannot be cached; at this scale that is"
  },
  {
    "file": "docs/architecture.md",
    "line": 66,
    "claim": "**Ledger import is offline and separate.** 232,000 ledger entries cannot be"
  },
  {
    "file": "docs/architecture.md",
    "line": 73,
    "claim": "exposes query parameters, path parameters or request headers. Every addressable"
  },
  {
    "file": "docs/architecture.md",
    "line": 80,
    "claim": "and applied to every interpolated value. Verified against an injection attempt"
  },
  {
    "file": "docs/architecture.md",
    "line": 88,
    "claim": "| `database` | every `store_*` operation |"
  },
  {
    "file": "docs/domain_model.md",
    "line": 3,
    "claim": "Every term below already existed somewhere in the Howl ecosystem. HowlBoard"
  },
  {
    "file": "docs/domain_model.md",
    "line": 45,
    "claim": "(`src/control_plane/authority_envelope.py`), **derived on every read**:"
  },
  {
    "file": "docs/domain_model.md",
    "line": 125,
    "claim": "is contract-tested: `claimed` must never be reported as `passed`."
  },
  {
    "file": "docs/domain_model.md",
    "line": 133,
    "claim": "`PURSUE` / `REJECT` / `DEFER` / `REQUIRES_HUMAN` / `NO_VALUABLE_ACTION`. None of"
  }
]
```

Recommended remediation (for the artifact's owner, not for HowlProof): Qualify the claim, or add a check that would fail if it stopped being true.

Reproduction: Re-run docs.claims against the artifact.

1. Re-scan the declared documentation for unqualified absolute claims.


## Unresolved risks

- HP-SEC-0001 (MEDIUM): .github/workflows/ci.yml runs actions/checkout at `v4`, a tag or branch the action's owner can repoint at any time. A compromised or retagged action executes with this workflow's token.
- HP-SEC-0002 (MEDIUM): .github/workflows/ci.yml runs actions/setup-go at `v5`, a tag or branch the action's owner can repoint at any time. A compromised or retagged action executes with this workflow's token.
- HP-SEC-0003 (MEDIUM): .github/workflows/ci.yml runs actions/setup-python at `v5`, a tag or branch the action's owner can repoint at any time. A compromised or retagged action executes with this workflow's token.
- HP-SEC-0004 (MEDIUM): Without an explicit `permissions:` block the workflow inherits the repository default, which may grant write access to contents, packages and more than the job needs.
- HP-SEC-0005 (MEDIUM): A call to `set_html` assembles HTML containing an interpolated value and no escape function appears in the surrounding expression.
- HP-SEC-0006 (HIGH): `esc` escapes ", &, <, > and not the single quote (defined at frontend/mission_view.howl:64). At frontend/mission_view.howl:134 its output is placed inside a single-quoted JavaScript string in an event-handler attribute. The HTML parser decodes the attribute before JavaScript parses it, so a single quote in the value terminates the string literal and everything after it becomes code. Escaping the double quote prevents breaking out of the attribute; it does not prevent breaking out of the string.
- HP-SEC-0007 (HIGH): A mission identifier carrying a single quote, placed in the fixture the seed endpoint loads. Identifiers created through the API are server assigned, but seeded and ledger-imported records keep whatever identifier the source document carried.. A value placed at /missions/0/id in data/fixtures/missions.json and loaded through the artifact's own seed path set `window.__howlproof_injection` when the interface rendered it, which means the value was parsed as code rather than displayed as text.
- HP-OPS-0001 (MEDIUM): index.html@375: the document scrolls horizontally

## Limitations

- sast.bandit was UNAVAILABLE: the artifact has no pyproject.toml to install
- deps.audit was NOT_APPLICABLE: the artifact declares no Python dependencies to audit
- cli.destructive was NOT_APPLICABLE: the artifact declares no destructive subcommands to inspect
- release.version was NOT_APPLICABLE: the artifact has no pyproject.toml declaring a version
- reliability.corrupt_store observed a simulation, not the real dependency

--------------------------------------------------------------------

This report is advisory evidence. HowlProof does not promote, merge, deploy or approve anything. Remediation belongs to the artifact's builder and promotion to HowlPlane and HowlChangeOps.
