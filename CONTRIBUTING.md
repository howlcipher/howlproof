# Contributing

Keep evaluations local-first and bounded. Security checks stay defensive: they
probe artifacts the operator points at, on the operator's machine, and no
exploitation tooling ships here.

Every new evaluator declares the tools it needs, probes their availability before
running, and reports UNAVAILABLE rather than passing when they are absent. Every
check result carries a limitation. Every finding carries evidence, and CONFIRMED
confidence carries a reproduction.

New behavior needs a failing contract test first. Add the defect to
tests/fixtures/vulnerable_app and the correct shape to tests/fixtures/clean_app,
then assert both. Run the README verification commands, update README.md and
change_log.md, and use signed conventional commits. No credentials in CI.
