# Vendored ecosystem schemas

Copies of HowlPlane's contract schemas, taken from `howlcipher/howlplane` on
11 September 2026. `tests/test_handoff.py` validates every document HowlProof
emits against them, so "these are the schemas the ecosystem already reads" is a
tested statement rather than an assertion.

Pinning a copy is safe because these are closed contracts. HowlPlane's own
specification requires that a field from a future revision bump the `schema`
constant rather than append onto `v1`:

> Unknown top-level fields are rejected. All five schemas set
> `additionalProperties: false`. This is a deliberate difference: these are
> closed, versioned contracts, and a field from a future schema revision must
> bump the `schema` constant rather than append silently onto `v1`.
>
> — `howlplane/documentation/TASK_EVENT_SPEC.md`

A `v2` would therefore be a new file here, not an edit to these.

Refresh with:

```bash
cp ../howlplane/schemas/{review-finding,evidence-entry,verification-plan}.schema.json \
   tests/ecosystem_schemas/
```
