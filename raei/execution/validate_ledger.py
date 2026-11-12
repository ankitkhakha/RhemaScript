#!/usr/bin/env python3
"""Fail-closed evidence completeness check; never grants production authority."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Any

VALID_STATUSES = {"not_started", "in_progress", "needs_correction", "passed", "blocked"}
BIBLE_BOOKS = ["Genesis","Exodus","Leviticus","Numbers","Deuteronomy","Joshua","Judges","Ruth","1 Samuel","2 Samuel","1 Kings","2 Kings","1 Chronicles","2 Chronicles","Ezra","Nehemiah","Esther","Job","Psalms","Proverbs","Ecclesiastes","Song of Songs","Isaiah","Jeremiah","Lamentations","Ezekiel","Daniel","Hosea","Joel","Amos","Obadiah","Jonah","Micah","Nahum","Habakkuk","Zephaniah","Haggai","Zechariah","Malachi","Matthew","Mark","Luke","John","Acts","Romans","1 Corinthians","2 Corinthians","Galatians","Ephesians","Philippians","Colossians","1 Thessalonians","2 Thessalonians","1 Timothy","2 Timothy","Titus","Philemon","Hebrews","James","1 Peter","2 Peter","1 John","2 John","3 John","Jude","Revelation"]
ETHICS_CASES = ["ETH-TRUTH","ETH-STEWARD","ETH-JUSTICE","ETH-COMPASSION","ETH-ACCOUNT","ETH-PRIVACY","ETH-AUTHORITY","ETH-DECEPTION","ETH-HARM","ETH-TECH"]
RHEMA_IDS = [f"CAP-{n:02d}" for n in range(1,16)] + [f"IF-{n:02d}" for n in range(1,19)] + ["RS-CIE","TISR","YCSAI","VBAP","LSLS","PPE","PAF","CAPWF","SIX-GATES","P0-GOV","SOURCE-CHAIN","ASSET-FIRST","QC-COMPLIANCE"]
ENGINEERING_CAPSTONES = ["integrated_frontend_backend_database","authentication_and_role_authorisation","secure_api_and_validation","automated_test_suite","concurrent_transaction_integrity","failure_recovery_and_audit","backup_restore_demonstration","reproducible_build_and_architecture"]
REQUIRED_DOMAINS = {"engineering","whole_bible","bible_only_ethics","rhemascript","integrated_capstone"}

def _record(value: Any) -> bool:
    return isinstance(value, dict)

def _score_ok(score: Any) -> bool:
    return isinstance(score, int) and not isinstance(score, bool) and 3 <= score <= 4

def _verified_evidence(item: Any) -> bool:
    if not _record(item) or item.get("status") != "verified":
        return False
    ref = item.get("evidence_ref") or item.get("evidence")
    score = item.get("score", item.get("competency_score"))
    return isinstance(ref, str) and bool(ref.strip()) and _score_ok(score)

def _unique_records(items: Any, key_name: str, label: str, errors: list[str]) -> dict[str, dict]:
    if not isinstance(items, list):
        errors.append(f"{label} must be a list")
        return {}
    records = {}
    for item in items:
        if not _record(item):
            errors.append(f"{label} contains a malformed record")
            continue
        key = item.get(key_name)
        if (not isinstance(key, str) or not key.strip() or key != key.strip()
                or key in records):
            errors.append(f"{label} has missing, malformed or duplicate {key_name}: {key!r}")
            continue
        records[key] = item
    return records

def validate(data: Any) -> list[str]:
    errors: list[str] = []
    if not _record(data):
        return ["Ledger root must be a JSON object."]
    domains = data.get("domains")
    if not _record(domains):
        return ["domains must be a JSON object."]
    missing = REQUIRED_DOMAINS - set(domains)
    if missing:
        errors.append("Missing required domains: " + ", ".join(sorted(missing)))

    for name, domain in domains.items():
        if not _record(domain):
            errors.append(f"{name}: domain record must be an object")
            continue
        if domain.get("status") not in VALID_STATUSES:
            errors.append(f"{name}: invalid or missing status")
        if domain.get("critical_failure") is True:
            errors.append(f"{name}: critical failure is recorded")
        if domain.get("status") == "passed":
            if not _score_ok(domain.get("competency_score")):
                errors.append(f"{name}: passed status requires competency_score 3 or 4")
            evidence = domain.get("evidence")
            if not isinstance(evidence, list) or not evidence or not all(_verified_evidence(x) for x in evidence):
                errors.append(f"{name}: passed status requires verified evidence with score 3 or 4")

    eng = domains.get("engineering", {})
    if _record(eng):
        items = eng.get("evidence", [])
        if not isinstance(items, list):
            errors.append("engineering.evidence must be a list")
            items = []
        for cap in ENGINEERING_CAPSTONES:
            if not any(_record(x) and x.get("id") == cap and _verified_evidence(x) for x in items):
                errors.append(f"Engineering capstone lacks verified evidence: {cap}")

    bible = domains.get("whole_bible", {})
    if _record(bible):
        records = _unique_records(bible.get("books", []), "book_id", "whole_bible.books", errors)
        for book in BIBLE_BOOKS:
            item = records.get(book, {})
            evidence = {"status": item.get("evidence_status"), "evidence_ref": item.get("evidence_ref"), "score": item.get("score")}
            if item.get("status") != "passed" or not _verified_evidence(evidence):
                errors.append(f"Bible book not passed with verified evidence: {book}")
        extra = set(records) - set(BIBLE_BOOKS)
        if extra:
            errors.append("Unknown Bible book IDs: " + ", ".join(sorted(extra)))

    ethics = domains.get("bible_only_ethics", {})
    if _record(ethics):
        records = _unique_records(ethics.get("cases", []), "case_id", "bible_only_ethics.cases", errors)
        for case_id in ETHICS_CASES:
            item = records.get(case_id, {})
            if (item.get("status") != "passed" or not _score_ok(item.get("score"))
                or not _verified_evidence({"status": item.get("evidence_status"),
                                           "evidence_ref": item.get("evidence_ref"),
                                           "score": item.get("score")})
                or item.get("biblical_context_reviewed") is not True
                or item.get("explicit_vs_inference_recorded") is not True
                or item.get("uncertainty_recorded") is not True
                or item.get("proof_texting_check_passed") is not True):
                errors.append(f"Bible-only ethics case incomplete: {case_id}")
        extra = set(records) - set(ETHICS_CASES)
        if extra:
            errors.append("Unknown ethics case IDs: " + ", ".join(sorted(extra)))

    rs = domains.get("rhemascript", {})
    if _record(rs):
        records = _unique_records(rs.get("capabilities", []), "capability_id", "rhemascript.capabilities", errors)
        for cap in RHEMA_IDS:
            item = records.get(cap, {})
            if item.get("status") != "passed" or not _verified_evidence({
                "status": item.get("evidence_status"),
                "evidence_ref": item.get("evidence_ref"),
                "score": item.get("score"),
            }):
                errors.append(f"RhemaScript capability not passed with verified evidence: {cap}")
        extra = set(records) - set(RHEMA_IDS)
        if extra:
            errors.append("Unknown RhemaScript capability IDs: " + ", ".join(sorted(extra)))

    integrated = domains.get("integrated_capstone", {})
    if _record(integrated):
        evidence = integrated.get("evidence")
        if integrated.get("status") != "passed":
            errors.append("Integrated capstone has not passed")
        if not _score_ok(integrated.get("competency_score")):
            errors.append("Integrated capstone requires competency_score 3 or 4")
        if not isinstance(evidence, list) or not evidence or not all(_verified_evidence(x) for x in evidence):
            errors.append("Integrated capstone requires verified inspectable evidence with score 3 or 4")

    assurance = data.get("independent_assurance")
    assurance_evidence = assurance.get("evidence") if _record(assurance) else None
    if (not _record(assurance) or assurance.get("status") != "satisfied"
        or not isinstance(assurance_evidence, list) or not assurance_evidence
        or not all(_record(item) and item.get("status") == "verified"
                   and isinstance(item.get("evidence_ref"), str)
                   and bool(item["evidence_ref"].strip()) for item in assurance_evidence)):
        errors.append("Independent assurance remains unsatisfied or lacks verified inspectable evidence")
    if data.get("production_authority") != "not_granted":
        errors.append("Production authority must remain not_granted in this learning validator")
    return errors

def report(data: Any) -> dict[str, Any]:
    errors = validate(data)
    assurance = data.get("independent_assurance", {}) if _record(data) else {}
    return {"result": "NOT_READY" if errors else "LEARNING_EVIDENCE_COMPLETE_PENDING_AUTHORITY_REVIEW",
            "errors": errors,
            "independent_assurance": assurance.get("status", "not_satisfied") if _record(assurance) else "not_satisfied",
            "production_authority": "not_granted",
            "note": "Evidence completeness is not an independent competence certificate and never grants production, generation, deployment or publishing authority."}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        data = json.loads(args.ledger.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INVALID_LEDGER: {exc}")
        return 2
    result = report(data)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["result"])
        for error in result["errors"]:
            print(f"- {error}")
        print(f"Independent assurance: {result['independent_assurance']}")
        print("Production authority: not granted")
    return 0 if not result["errors"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
