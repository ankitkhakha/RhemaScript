"""Command-line interface for the non-authorising project integrity validator."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .validate_project_integrity import readiness_report


def load_record(path: Path) -> Any:
    """Load one UTF-8 JSON project record; malformed files raise clear errors."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read project record: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check project traceability without granting production authority."
    )
    parser.add_argument("record", type=Path, help="UTF-8 JSON project-readiness record")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    args = parser.parse_args(argv)

    try:
        result = readiness_report(load_record(args.record))
    except ValueError as exc:
        print(f"INVALID_RECORD: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(result["result"])
        for blocker in result["blockers"]:
            print(f"- {blocker}")
        print(f"Generation executed: {result['generation_executed']}")
        print(f"Publishing executed: {result['publishing_executed']}")
        print(f"Production authority: {result['production_authority']}")
        print(result["note"])
    return 0 if result["result"] == "PROJECT_TRACEABILITY_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
