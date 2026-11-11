"""RAEI curriculum execution orchestrator.

The orchestrator seeds the approved registry into the existing evidence ledger,
selects the next prerequisite-ready task, and renders an execution brief. It
never invents evidence, scores work, grants authority, or executes arbitrary code.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .curriculum import build_registry
from .ledger import (
    LedgerError, append_event, empty_ledger, load, report, save,
    validate,
)
from .learning import record_practice, record_rubric_assessment

DOMAIN_ORDER = (
    "engineering",
    "whole_bible",
    "bible_only_ethics",
    "rhemascript",
    "integrated",
)


def seed_ledger() -> dict[str, Any]:
    """Create a complete curriculum ledger without claiming any learning."""
    data = empty_ledger()
    registry = build_registry()
    for item in registry:
        data["units"][item["id"]] = {
            "id": item["id"],
            "title": item["title"],
            "domain": item["domain"],
            "prerequisites": list(item.get("prerequisites", [])),
            "status": "not_started",
            "score": None,
            "evidence_ref": None,
            "evidence_status": None,
            "objectives": item["objectives"],
            "source_refs": item["source_refs"],
            "practice_prompt": item["practice_prompt"],
            "rubric": item["rubric"],
            "evidence_required": True,
        }
    append_event(data, "curriculum_seeded", None, {
        "unit_count": len(registry),
        "domains": list(DOMAIN_ORDER),
        "mastery_claim": False,
    })
    validate(data)
    return data


def next_unit(data: dict[str, Any]) -> dict[str, Any] | None:
    """Select the earliest incomplete unit using a stable domain rotation."""
    validate(data)
    units = data["units"]
    for domain in DOMAIN_ORDER:
        candidates = [
            unit for unit in units.values()
            if unit.get("domain") == domain
            and unit.get("status") in {"not_started", "in_progress", "needs_correction"}
            and all(units[p]["status"] == "passed" for p in unit.get("prerequisites", []))
        ]
        if candidates:
            return candidates[0]
    return None


def execution_brief(unit: dict[str, Any]) -> dict[str, Any]:
    """Return an actionable task, not fabricated lesson content or evidence."""
    return {
        "unit_id": unit["id"],
        "title": unit["title"],
        "domain": unit["domain"],
        "status": unit["status"],
        "objectives": unit["objectives"],
        "source_refs": unit["source_refs"],
        "task": unit["practice_prompt"],
        "required_deliverables": [
            "original_work_or_study",
            "method_and_execution_context",
            "inspectable_result",
            "limitations_and_corrections",
        ],
        "assessment_rubric": unit["rubric"],
        "pass_rule": "minimum 3/4 on every rubric criterion, verified evidence, no critical failure",
        "evidence_rule": "Do not record passed until the artefact and result are inspectable.",
        "authority_boundary": {
            "production_authority": "not_granted",
            "media_generation": "not_authorised_by_learning_task",
            "publishing": "not_authorised_by_learning_task",
        },
    }


def initialise(path: str, force: bool = False) -> dict[str, Any]:
    target = Path(path)
    if target.exists() and not force:
        raise LedgerError(f"refusing to overwrite existing ledger: {path}")
    data = seed_ledger()
    save(target, data)
    return report(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="raei")
    parser.add_argument("--ledger", default="raei-learning-ledger.json")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--force", action="store_true")
    commands.add_parser("next")
    show = commands.add_parser("show")
    show.add_argument("unit_id")
    commands.add_parser("status")
    practice = commands.add_parser("practice")
    practice.add_argument("unit_id")
    practice.add_argument("artifact_ref")
    practice.add_argument("method")
    practice.add_argument("result")
    practice.add_argument("--evidence-status", choices=["verified", "reported_unverified", "planned"], default="reported_unverified")
    assess = commands.add_parser("assess")
    assess.add_argument("unit_id")
    assess.add_argument("criterion_scores", help="JSON object mapping every rubric criterion to a score from 0 to 4")
    assess.add_argument("evidence_ref")
    assess.add_argument("--evidence-status", choices=["verified", "reported_unverified", "planned"], default="verified")
    assess.add_argument("--note", default="")
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            result = initialise(args.ledger, args.force)
        else:
            data = load(args.ledger)
            if args.command == "next":
                unit = next_unit(data)
                result = {"next_task": execution_brief(unit) if unit else None}
            elif args.command == "show":
                if args.unit_id not in data["units"]:
                    raise LedgerError(f"unknown unit: {args.unit_id}")
                result = execution_brief(data["units"][args.unit_id])
            elif args.command == "practice":
                record_practice(data, args.unit_id, args.artifact_ref, args.method, args.result,
                                status=args.evidence_status)
                save(args.ledger, data)
                result = {"recorded": "practice", "unit_id": args.unit_id,
                          "status": data["units"][args.unit_id]["status"]}
            elif args.command == "assess":
                try:
                    scores = json.loads(args.criterion_scores)
                except json.JSONDecodeError as exc:
                    raise LedgerError(f"criterion_scores must be valid JSON: {exc}") from exc
                if not isinstance(scores, dict):
                    raise LedgerError("criterion_scores must be a JSON object")
                record_rubric_assessment(data, args.unit_id, scores, args.evidence_ref,
                                         args.evidence_status, args.note)
                save(args.ledger, data)
                result = {"recorded": "assessment", "unit_id": args.unit_id,
                          "status": data["units"][args.unit_id]["status"],
                          "score": data["units"][args.unit_id]["score"],
                          "criterion_scores": data["units"][args.unit_id]["criterion_scores"]}
            else:
                result = report(data)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except LedgerError as exc:
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
