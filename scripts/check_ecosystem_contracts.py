"""Detect semantic drift in the upstream schemas, including additive v1 edits."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

NAMES = tuple(
    f"{name}.schema.json" for name in ("review-finding", "evidence-entry", "verification-plan")
)
VENDOR = Path(__file__).resolve().parents[1] / "tests/ecosystem_schemas"


def differences(upstream: Path, vendor: Path = VENDOR) -> list[str]:
    """Ignore formatting, but report every changed or missing contract."""
    changed = []
    for name in NAMES:
        try:
            same = json.loads((upstream / name).read_text()) == json.loads(
                (vendor / name).read_text()
            )
        except (OSError, ValueError):
            same = False
        if not same:
            changed.append(name)
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plane-root", type=Path, required=True)
    args = parser.parse_args()
    changed = differences(args.plane_root / "schemas")
    print(
        json.dumps({"drift": changed, "policy": "semantic equality; review additive changes too"})
    )
    return int(bool(changed))


if __name__ == "__main__":
    raise SystemExit(main())
