#!/usr/bin/env python3
"""Local IF-18 read-only validation and redacted certification report.

This harness uses synthetic tests only. It never loads operator credentials or
contacts Google. Live channel verification remains a separate owner-run action.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_OPERATIONS = {"OAUTH_TOKEN", "CHANNEL_READ"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-file",
        help="optional path for a JSON certification report (no secrets or channel identifiers)",
    )
    args = parser.parse_args(argv)

    checks: dict[str, dict[str, object]] = {}
    try:
        sys.path.insert(0, str(ROOT))
        from rhemascript.integrations.connection import read_only_youtube_binding

        binding = read_only_youtube_binding()
        actual = set(binding.operations)
        checks["if18_read_only_allowlist"] = {
            "status": "PASS" if binding.interface_id == "IF-18" and actual == EXPECTED_OPERATIONS else "FAIL",
            "interface_id": binding.interface_id,
            "operations": sorted(actual),
            "publishing_operations_present": bool(actual - EXPECTED_OPERATIONS),
        }
    except Exception as exc:
        checks["if18_read_only_allowlist"] = {
            "status": "FAIL",
            "error_type": type(exc).__name__,
        }

    test_run = subprocess.run(
        [sys.executable, "ci/run_ci.py"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    checks["full_contract_and_synthetic_test_suite"] = {
        "status": "PASS" if test_run.returncode == 0 else "FAIL",
        "exit_code": test_run.returncode,
        "runner": "ci/run_ci.py",
    }

    passed = all(item.get("status") == "PASS" for item in checks.values())
    report = {
        "schema": "RhemaScript.IF18.ReadOnlyValidationReport.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "overall_status": "PASS" if passed else "FAIL",
        "validation_mode": "SYNTHETIC_ONLY",
        "live_google_connection_attempted": False,
        "publishing_enabled": False,
        "checks": checks,
        "limitations": [
            "This report validates local code contracts and synthetic tests only.",
            "It does not prove live OAuth consent, account access, or channel identity.",
            "A channel owner must run the separate read-only connection command locally.",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")

    if args.report_file:
        destination = Path(args.report_file).expanduser()
        try:
            if destination.exists() and destination.is_symlink():
                raise OSError("report destination must not be a symlink")
            destination.write_text(rendered, encoding="utf-8")
        except OSError:
            print("Could not write validation report to the requested path.", file=sys.stderr)
            return 2

    # Keep raw test output out of the certification report and normal console
    # result; emit only a bounded failure hint for troubleshooting.
    if test_run.returncode:
        tail = "\n".join(test_run.stdout.splitlines()[-12:])
        print("TEST RUNNER FAILURE (last 12 lines):", file=sys.stderr)
        print(tail, file=sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
