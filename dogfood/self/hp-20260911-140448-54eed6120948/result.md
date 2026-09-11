# HowlProof result

HowlProof judges. It does not repair the artifact it is judging.

Artifact: howlproof
Commit: 1b67d003e70c13af05a0e25407f497d6802c1270
Branch: main
Run: hp-20260911-140448-54eed6120948
Profiles: python, security, documentation, web
Completed: 2026-09-11T14:07:55.565848+00:00

## Verdict: CONDITIONALLY_PROVEN

The artifact passed subject to documented assumptions, exclusions, environment limitations or unresolved non-blocking findings, each named in the result.

Deciding rule: `conditional`

- deps.audit was SKIPPED: a dependency audit queries a remote advisory database and network access was not granted with --allow-network; no vulnerability was checked for and none is implied to be absent
- markup.escaping did not apply: the artifact declares no markup sources to analyse
- http.authz did not apply: the artifact declares no service, so there is nothing to reach
- web.dom_injection did not apply: the artifact declares no injection payloads to attempt
- cli.destructive did not apply: the artifact declares no destructive subcommands to inspect

## Acceptance criteria

6 of 6 satisfied.

| Criterion | Requirement | Outcome | Detail |
| --- | --- | --- | --- |
| AC-01 | checks_pass | SATISFIED | 4 required checks verified |
| AC-02 | max_findings | SATISFIED | 0 security findings at or above HIGH, limit 0 |
| AC-03 | tool_required | SATISFIED | 1 required tools present |
| AC-04 | no_regressions | SATISFIED | no previously fixed finding reappeared |
| AC-05 | coverage_floor | SATISFIED | 12 of 13 applicable checks were conclusive (0.92), floor 0.60 |
| AC-06 | checks_pass | SATISFIED | 2 required checks verified |

## Checks

11 verified, 1 failed, 1 skipped, 0 unavailable, 4 not applicable, 0 errored.

| Check | Checker | Status | Mode | Note |
| --- | --- | --- | --- | --- |
| python.lint | python.lint/v1 | VERIFIED | REAL | `.howlproof-venv/bin/python -m ruff check .` exited 0 |
| python.types | python.types/v1 | VERIFIED | REAL | `.howlproof-venv/bin/python -m mypy` exited 0 |
| python.tests | python.tests/v1 | VERIFIED | REAL | `.howlproof-venv/bin/python -m pytest -q` exited 0 |
| python.build | python.build/v1 | VERIFIED | REAL | `.howlproof-venv/bin/python -m build --outdir .howlproof-dist` exited 0 |
| release.version | release.version/v1 | VERIFIED | REAL | the declared version, package attribute and changelog agree |
| sast.bandit | sast.bandit/v1 | VERIFIED | REAL | bandit reports no medium or high findings in . |
| deps.audit | deps.audit/v1 | SKIPPED | REAL | a dependency audit queries a remote advisory database and network access was not granted with --allow-network; no vulnerability was checked for and none is implied to be absent |
| secrets.scan | secrets.scan/v1 | FAILED | REAL | 3 credential-shaped strings in 181 text files |
| ci.supplychain | ci.supplychain/v1 | VERIFIED | REAL | 2 workflows pin their actions, scope permissions and keep untrusted expressions out of run blocks |
| markup.escaping | markup.escaping/v1 | NOT_APPLICABLE | REAL | the artifact declares no markup sources to analyse |
| http.authz | http.authz/v1 | NOT_APPLICABLE | REAL | the artifact declares no service, so there is nothing to reach |
| web.dom_injection | web.dom_injection/v1 | NOT_APPLICABLE | REAL | the artifact declares no injection payloads to attempt |
| docs.claims.absolutes | docs.claims/v1 | VERIFIED | REAL | 34 absolute documentation claims collected for challenge |
| cli.destructive | cli.destructive/v1 | NOT_APPLICABLE | REAL | the artifact declares no destructive subcommands to inspect |
| web.links | web.links/v1 | VERIFIED | REAL | all 56 references resolve |
| web.metadata | web.metadata/v1 | VERIFIED | REAL | 1 pages carry title, description, canonical, Open Graph tags and a single h1, alongside robots.txt and sitemap.xml |
| web.responsive | web.responsive/v1 | VERIFIED | REAL | 1 pages render at 375px, 768px, 1440px with one h1, a main landmark, resolvable fragments, keyboard entry and no horizontal overflow |

## Validation modes

- **REAL**: python.lint, python.types, python.tests, python.build, release.version, sast.bandit, secrets.scan, ci.supplychain, docs.claims.absolutes, web.links, web.metadata, web.responsive
- **SIMULATED**: none
- **SKIPPED**: deps.audit
- **UNAVAILABLE**: none
- **NOT_APPLICABLE**: markup.escaping, http.authz, web.dom_injection, cli.destructive
- **ERROR**: none

## Findings

### HP-SEC-0001 — Credential-shaped github_token in tests/fixtures/vulnerable_app/src/config.py

- Adversary: SECURITY
- Category: security
- Severity: BLOCKER
- Confidence: HIGH
- State: ACCEPTED_RISK
- Blocking: no
- Location: tests/fixtures/vulnerable_app/src/config.py:3

A string matching the github_token credential format appears at tests/fixtures/vulnerable_app/src/config.py:3. The path suggests a fixture, so this may be intentional test data.

Evidence:

```
ith a credential committed in the open."""

GITHUB_[REDACTED] chars redacted]"
DATABASE_PASSWORD
```

Recommended remediation (for the artifact's owner, not for HowlProof): Remove the value from the tree, rotate it if it was ever real, and load it from the environment or a secret store instead.

Reproduction: Re-read the file and match the same pattern.

1. Search tests/fixtures/vulnerable_app/src/config.py for the github_token pattern.

### HP-SEC-0002 — Credential-shaped github_token in tests/test_cli.py

- Adversary: SECURITY
- Category: security
- Severity: BLOCKER
- Confidence: HIGH
- State: ACCEPTED_RISK
- Blocking: no
- Location: tests/test_cli.py:322

A string matching the github_token credential format appears at tests/test_cli.py:322. The path suggests a fixture, so this may be intentional test data.

Evidence:

```
/ "src" / "config.py").write_text(
        config.replace('"ghp_...[40 chars redacted]"', 'os.environ["GIT
```

Recommended remediation (for the artifact's owner, not for HowlProof): Remove the value from the tree, rotate it if it was ever real, and load it from the environment or a secret store instead.

Reproduction: Re-read the file and match the same pattern.

1. Search tests/test_cli.py for the github_token pattern.

### HP-SEC-0003 — Credential-shaped assigned_credential in tests/test_contracts.py

- Adversary: SECURITY
- Category: security
- Severity: LOW
- Confidence: HIGH
- State: ACCEPTED_RISK
- Blocking: no
- Location: tests/test_contracts.py:285

A string matching the assigned_credential credential format appears at tests/test_contracts.py:285. The path suggests a fixture, so this may be intentional test data.

Evidence:

```
36,
        "[REDACTED]",
        'pass...[31 chars redacted]',
    ],
)
def test
```

Recommended remediation (for the artifact's owner, not for HowlProof): Remove the value from the tree, rotate it if it was ever real, and load it from the environment or a secret store instead.

Reproduction: Re-read the file and match the same pattern.

1. Search tests/test_contracts.py for the assigned_credential pattern.

### HP-OPS-0002 — 34 absolute documentation claims are unverified

- Adversary: OPERATOR
- Category: other
- Severity: INFORMATIONAL
- Confidence: CONFIRMED
- State: FOUND
- Blocking: no
- Location: not localised

The documentation asserts these without qualification. Each one is a promise a single counterexample breaks, and this evaluation did not independently establish any of them: README.md:46 | `PROVEN` | 0 | Every acceptance criterion was satisfied, no unresolved finding sits abov; README.md:48 | `REQUIRES_HUMAN` | 20 | The evidence cannot safely support an autonomous decision |; README.md:91 Four of these are not passes and none of them is silent. Every check also records; README.md:93 never reads like a clean result.; README.md:122 howlproof accept HP-SEC-0001 --reason "Authored fixture data; the value was never valid."; README.md:128 keeps appearing in every report. There is no way to make one disappear quietly.

Evidence:

```
[
  {
    "file": "README.md",
    "line": 46,
    "claim": "| `PROVEN` | 0 | Every acceptance criterion was satisfied, no unresolved finding sits above the permitted threshold, and enough checks actually executed to justify saying so |"
  },
  {
    "file": "README.md",
    "line": 48,
    "claim": "| `REQUIRES_HUMAN` | 20 | The evidence cannot safely support an autonomous decision |"
  },
  {
    "file": "README.md",
    "line": 91,
    "claim": "Four of these are not passes and none of them is silent. Every check also records"
  },
  {
    "file": "README.md",
    "line": 93,
    "claim": "never reads like a clean result."
  },
  {
    "file": "README.md",
    "line": 122,
    "claim": "howlproof accept HP-SEC-0001 --reason \"Authored fixture data; the value was never valid.\""
  },
  {
    "file": "README.md",
    "line": 128,
    "claim": "keeps appearing in every report. There is no way to make one disappear quietly."
  },
  {
    "file": "README.md",
    "line": 139,
    "claim": "state the finding was raised against, because an unchanged artifact cannot have"
  },
  {
    "file": "README.md",
    "line": 144,
    "claim": "A statement that a defect was repaired never produces `VERIFIED_FIXED`. Only a"
  },
  {
    "file": "README.md",
    "line": 153,
    "claim": "environment.json  every tool probed, and why an absent one is absent"
  },
  {
    "file": "README.md",
    "line": 163,
    "claim": "`howlproof inspect <bundle>` re-reads the bundle and recomputes every hash in its"
  },
  {
    "file": "README.md",
    "line": 208,
    "claim": "failure, never a silent skip. Any active exclusion prevents `PROVEN` and an"
  },
  {
    "file": "README.md",
    "line": 221,
    "claim": "and written into the workspace copy, never the artifact."
  },
  {
    "file": "README.md",
    "line": 232,
    "claim": "1. Evaluators never receive a writable handle to the artifact. The tree is"
  },
  {
    "file": "README.md",
    "line": 233,
    "claim": "materialised into a workspace copy and every command runs there."
  },
  {
    "file": "README.md",
    "line": 256,
    "claim": "Every handoff carries `authority: ADVISORY`. HowlProof issues verdicts; HowlPlane"
  },
  {
    "file": "README.md",
    "line": 268,
    "claim": "deserves and a finding from it is never `CONFIRMED`."
  },
  {
    "file": "README.md",
    "line": 278,
    "claim": "- **HowlProof is not an autonomous repair agent.** It never edits the artifact it"
  },
  {
    "file": "README.md",
    "line": 313,
    "claim": "- [Evaluators](docs/evaluators.md) \u2014 every check, what it establishes and what it does not"
  },
  {
    "file": "ROADMAP.md",
    "line": 38,
    "claim": "- Cross-artifact regression: replaying every `VERIFIED_FIXED` reproduction across"
  },
  {
    "file": "docs/contract.md",
    "line": 35,
    "claim": "**Evaluators cannot write to the artifact.** `Target.prepare` materialises the"
  }
]
```

Recommended remediation (for the artifact's owner, not for HowlProof): Qualify the claim, or add a check that would fail if it stopped being true.

Reproduction: Re-run docs.claims against the artifact.

1. Re-scan the declared documentation for unqualified absolute claims.


## Unresolved risks

None recorded.

## Limitations

- deps.audit was SKIPPED: a dependency audit queries a remote advisory database and network access was not granted with --allow-network; no vulnerability was checked for and none is implied to be absent
- markup.escaping was NOT_APPLICABLE: the artifact declares no markup sources to analyse
- http.authz was NOT_APPLICABLE: the artifact declares no service, so there is nothing to reach
- web.dom_injection was NOT_APPLICABLE: the artifact declares no injection payloads to attempt
- cli.destructive was NOT_APPLICABLE: the artifact declares no destructive subcommands to inspect

## Notes

- no service is declared, so live adversaries have nothing to attack

--------------------------------------------------------------------

This report is advisory evidence. HowlProof does not promote, merge, deploy or approve anything. Remediation belongs to the artifact's builder and promotion to HowlPlane and HowlChangeOps.
