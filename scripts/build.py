from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, load_rules, render_outputs, validate_rules, write_outputs


def build(output_dir: Path) -> dict[str, str]:
    rules = load_rules()
    errors = validate_rules(rules)
    if errors:
        raise SystemExit("Input validation failed:\n- " + "\n- ".join(errors))
    outputs = render_outputs(rules)
    write_outputs(outputs, output_dir)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Build deterministic CN direct-rule files")
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "dist", help="output directory"
    )
    args = parser.parse_args()
    outputs = build(args.output_dir)
    print(f"Generated {len(outputs)} files in {args.output_dir}")


if __name__ == "__main__":
    main()
