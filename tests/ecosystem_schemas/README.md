# Vendored ecosystem schemas

Copied from `howlcipher/howlplane` revision
`b633199aff0ddd71f3ea3639d14e63c2e7a0c499`. `tests/test_handoff.py` validates
emitted documents against these independent schemas.

The evidence-entry action enum has expanded under v1. A stable schema identifier
therefore does not establish identical contents. The drift checker compares parsed
JSON, including additive changes, while ignoring formatting. A drift alert means
review is needed; it does not alone establish incompatibility.

```bash
python scripts/check_ecosystem_contracts.py --plane-root ../howlplane
```

The contract workflow runs pinned integration on pushes and pull requests and
checks upstream main weekly or on manual dispatch. After reviewing a change,
copy the three schema files from Plane, update this revision and the workflow pin,
and run the handoff and real CLI integration tests. Never regenerate schemas
from Proof's own emitted documents.
