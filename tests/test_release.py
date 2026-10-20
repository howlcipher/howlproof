"""Release version checks understand prerelease headings as well as stable releases."""

from howlproof.config import ProofConfig
from howlproof.evaluators.release import ReleaseVersion
from howlproof.evidence import Bundle
from howlproof.model import CheckStatus
from howlproof.registry import Context
from howlproof.target import Target


def test_matching_beta_release_is_not_reported_as_version_drift(tmp_path):
    root = tmp_path / "target"
    package = root / "src" / "fixture"
    package.mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname="fixture"\nversion="0.2.0b1"\n')
    (package / "__init__.py").write_text('__version__ = "0.2.0b1"\n')
    (root / "change_log.md").write_text("# Changelog\n\n## 0.2.0b1\n\nBeta release.\n")
    target = Target.prepare(root, tmp_path / "workspace")
    context = Context(
        target,
        ProofConfig(schema_version=1, artifact="fixture"),
        Bundle.create(tmp_path / "proof", root),
    )
    assert ReleaseVersion().evaluate(context).checks[0].status is CheckStatus.VERIFIED
