"""Local, append-only evidence ledger for RAEI learning work."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 1
STATUSES = {"not_started", "in_progress", "needs_correction", "passed", "blocked"}

class LedgerError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def empty_ledger():
    return {"schema_version": SCHEMA, "programme": "RAEI Evidence-Based Execution", "units": {}, "events": []}

def event_hash(event):
    return digest({k: v for k, v in event.items() if k != "hash"})

def verify_chain(events, units):
    previous = "GENESIS"
    for index, event in enumerate(events):
        if event.get("sequence") != index + 1:
            raise LedgerError(f"event sequence broken at position {index + 1}")
        if event.get("previous_hash") != previous:
            raise LedgerError(f"event predecessor mismatch at position {index + 1}")
        if event.get("hash") != event_hash(event):
            raise LedgerError(f"event hash mismatch at position {index + 1}")
        previous = event["hash"]
    if events and events[-1].get("state_hash") != digest(units):
        raise LedgerError("current ledger state does not match the final recorded event")

def validate(data):
    if data.get("schema_version") != SCHEMA:
        raise LedgerError("unsupported schema version")
    if not isinstance(data.get("units"), dict) or not isinstance(data.get("events"), list):
        raise LedgerError("units must be an object and events must be an array")
    verify_chain(data["events"], data["units"])
    for unit_id, unit in data["units"].items():
        if not unit_id or unit.get("id") != unit_id:
            raise LedgerError(f"invalid unit identity: {unit_id!r}")
        if unit.get("status") not in STATUSES:
            raise LedgerError(f"invalid status for {unit_id}")
        if not isinstance(unit.get("prerequisites", []), list):
            raise LedgerError(f"invalid prerequisites for {unit_id}")
        for prerequisite in unit.get("prerequisites", []):
            if prerequisite not in data["units"]:
                raise LedgerError(f"unknown prerequisite {prerequisite!r} for {unit_id}")
        if unit.get("status") == "passed":
            score = unit.get("score")
            evidence_ref = unit.get("evidence_ref")
            if (not isinstance(score, int) or isinstance(score, bool) or not 3 <= score <= 4
                or not isinstance(evidence_ref, str) or not evidence_ref.strip()
                or unit.get("evidence_status") != "verified"):
                raise LedgerError(f"passed unit {unit_id} lacks verified evidence or score >= 3")
            if any(data["units"][p]["status"] != "passed" for p in unit.get("prerequisites", [])):
                raise LedgerError(f"passed unit {unit_id} has incomplete prerequisites")

def append_event(data, action, unit_id, details):
    events = data["events"]
    event = {"sequence": len(events) + 1, "timestamp": now(), "action": action,
             "unit_id": unit_id, "details": details,
             "previous_hash": events[-1]["hash"] if events else "GENESIS",
             "state_hash": digest(data["units"])}
    event["hash"] = event_hash(event)
    events.append(event)

def save(path, data):
    validate(data)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise

def load(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LedgerError(f"ledger not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise LedgerError(f"invalid JSON: {exc}") from exc
    validate(data)
    return data

def add_unit(data, unit_id, title, prerequisites):
    if unit_id in data["units"]:
        raise LedgerError(f"duplicate unit id: {unit_id}")
    if not unit_id.strip() or not title.strip():
        raise LedgerError("unit id and title are required")
    if unit_id in prerequisites or len(set(prerequisites)) != len(prerequisites):
        raise LedgerError("self-dependency or duplicate prerequisite")
    for item in prerequisites:
        if item not in data["units"]:
            raise LedgerError(f"prerequisite does not exist: {item}")
        if data["units"][item]["status"] != "passed":
            raise LedgerError(f"prerequisite is not passed: {item}")
    data["units"][unit_id] = {"id": unit_id, "title": title, "prerequisites": prerequisites,
        "status": "not_started", "score": None, "evidence_ref": None, "evidence_status": None}
    append_event(data, "unit_created", unit_id, {"title": title, "prerequisites": prerequisites})

def record_assessment(data, unit_id, score, evidence_ref, evidence_status, note=""):
    if unit_id not in data["units"]:
        raise LedgerError(f"unknown unit: {unit_id}")
    unit = data["units"][unit_id]
    if unit["status"] == "passed":
        raise LedgerError("passed units are immutable; create a new versioned unit for reassessment")
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 4:
        raise LedgerError("score must be an integer from 0 to 4")
    if evidence_status not in {"verified", "reported_unverified", "planned"}:
        raise LedgerError("invalid evidence status")
    if evidence_status == "verified" and (not evidence_ref or not evidence_ref.strip()):
        raise LedgerError("verified evidence requires a non-empty evidence reference")
    if any(data["units"][p]["status"] != "passed" for p in unit["prerequisites"]):
        raise LedgerError("cannot assess unit before prerequisites pass")
    passed = score >= 3 and evidence_status == "verified"
    unit.update({"status": "passed" if passed else "needs_correction", "score": score,
                 "evidence_ref": evidence_ref, "evidence_status": evidence_status})
    append_event(data, "assessment_recorded", unit_id, {"score": score, "evidence_ref": evidence_ref,
        "evidence_status": evidence_status, "result": unit["status"], "note": note})

def report(data):
    counts = {status: 0 for status in STATUSES}
    for unit in data["units"].values():
        counts[unit["status"]] += 1
    ready = bool(data["units"]) and counts["passed"] == len(data["units"])
    return {"programme": data["programme"], "unit_count": len(data["units"]),
            "counts": counts, "learning_units_all_passed": ready,
            "production_authority": "not_granted", "event_count": len(data["events"])}

def main(argv=None):
    parser = argparse.ArgumentParser(prog="raei-ledger")
    parser.add_argument("--ledger", default="raei-ledger.json")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    add = commands.add_parser("add-unit")
    add.add_argument("id"); add.add_argument("title"); add.add_argument("--requires", action="append", default=[])
    assess = commands.add_parser("assess")
    assess.add_argument("id"); assess.add_argument("score", type=int); assess.add_argument("evidence_ref")
    assess.add_argument("--evidence-status", choices=["verified", "reported_unverified", "planned"], default="reported_unverified")
    assess.add_argument("--note", default="")
    commands.add_parser("report")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            if Path(args.ledger).exists():
                raise LedgerError("refusing to overwrite an existing ledger")
            data = empty_ledger()
            append_event(data, "ledger_initialized", None, {})
            save(args.ledger, data)
        else:
            data = load(args.ledger)
            if args.command == "add-unit":
                add_unit(data, args.id, args.title, args.requires)
            elif args.command == "assess":
                record_assessment(data, args.id, args.score, args.evidence_ref, args.evidence_status, args.note)
            save(args.ledger, data)
        print(json.dumps(report(load(args.ledger)), indent=2))
        return 0
    except LedgerError as exc:
        print(f"ERROR: {exc}")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
