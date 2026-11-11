#!/usr/bin/env python3
"""Strict evidence gate for RAEI learning readiness; never grants production authority."""
from __future__ import annotations
import argparse, json
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

def _evidence_ok(item: Any) -> bool:
    if not _record(item) or item.get("status") != "verified":
        return False
    ref = item.get("evidence_ref") or item.get("evidence")
    score = item.get("score", item.get("competency_score", 3))
    return isinstance(ref, str) and bool(ref.strip()) and isinstance(score, int) and not isinstance(score, bool) and score >= 3

def validate(data: Any) -> list[str]:
    errors = []
    if not _record(data): return ["Ledger root must be a JSON object."]
    domains = data.get("domains")
    if not _record(domains): return ["domains must be a JSON object."]
    missing = REQUIRED_DOMAINS - set(domains)
    if missing: errors.append("Missing required domains: " + ", ".join(sorted(missing)))
    for name, domain in domains.items():
        if not _record(domain):
            errors.append(f"{name}: domain record must be an object"); continue
        if domain.get("status") not in VALID_STATUSES: errors.append(f"{name}: invalid or missing status")
        if domain.get("critical_failure") is True: errors.append(f"{name}: critical failure is recorded")
        if domain.get("status") == "passed":
            score = domain.get("competency_score")
            if not isinstance(score, int) or isinstance(score, bool) or score < 3: errors.append(f"{name}: passed status requires competency_score >= 3")
            if not isinstance(domain.get("evidence"), list) or not domain["evidence"]: errors.append(f"{name}: passed status requires evidence")

    eng = domains.get("engineering", {})
    if _record(eng):
        items = eng.get("evidence", [])
        required = eng.get("required_capstones", ENGINEERING_CAPSTONES)
        if not isinstance(required, list): errors.append("engineering.required_capstones must be a list"); required = ENGINEERING_CAPSTONES
        for cap in required:
            if not isinstance(items, list) or not any(_record(x) and x.get("id") == cap and _evidence_ok(x) for x in items):
                errors.append(f"Engineering capstone lacks verified evidence: {cap}")

    bible = domains.get("whole_bible", {})
    if _record(bible):
        books = bible.get("books", [])
        if not isinstance(books, list): errors.append("whole_bible.books must be a list"); books = []
        records = {}
        for item in books:
            if not _record(item): errors.append("whole_bible contains a malformed book record"); continue
            key = item.get("book_id")
            if not isinstance(key, str) or key in records: errors.append(f"whole_bible has missing or duplicate book_id: {key!r}"); continue
            records[key] = item
        for book in BIBLE_BOOKS:
            item = records.get(book, {})
            evidence = {"status": item.get("evidence_status"), "evidence_ref": item.get("evidence_ref"), "score": item.get("score")}
            if item.get("status") != "passed" or not _evidence_ok(evidence): errors.append(f"Bible book not passed with verified evidence: {book}")
        extra = set(records) - set(BIBLE_BOOKS)
        if extra: errors.append("Unknown Bible book IDs: " + ", ".join(sorted(extra)))

    ethics = domains.get("bible_only_ethics", {})
    if _record(ethics):
        cases = ethics.get("cases", [])
        if not isinstance(cases, list): errors.append("bible_only_ethics.cases must be a list"); cases = []
        records = {}
        for item in cases:
            if not _record(item): errors.append("bible_only_ethics contains a malformed case record"); continue
            key = item.get("case_id")
            if not isinstance(key, str) or key in records: errors.append(f"bible_only_ethics has missing or duplicate case_id: {key!r}"); continue
            records[key] = item
        for case_id in ETHICS_CASES:
            item = records.get(case_id, {})
            score, ref = item.get("score"), item.get("evidence_ref")
            if item.get("status") != "passed" or not isinstance(score, int) or isinstance(score, bool) or score < 3 or not isinstance(ref, str) or not ref.strip() or item.get("biblical_context_reviewed") is not True or item.get("explicit_vs_inference_recorded") is not True:
                errors.append(f"Bible-only ethics case incomplete: {case_id}")

    rs = domains.get("rhemascript", {})
    if _record(rs):
        caps = rs.get("capabilities", [])
        if not isinstance(caps, list): errors.append("rhemascript.capabilities must be a list"); caps = []
        records = {}
        for item in caps:
            if not _record(item): errors.append("rhemascript contains a malformed capability record"); continue
            key = item.get("capability_id")
            if not isinstance(key, str) or key in records: errors.append(f"rhemascript has missing or duplicate capability_id: {key!r}"); continue
            records[key] = item
        for cap in RHEMA_IDS:
            item = records.get(cap, {})
            score, ref = item.get("score"), item.get("evidence_ref")
            if item.get("status") != "passed" or not isinstance(score, int) or isinstance(score, bool) or score < 3 or not isinstance(ref, str) or not ref.strip():
                errors.append(f"RhemaScript capability not passed with evidence: {cap}")

    integrated = domains.get("integrated_capstone", {})
    if _record(integrated):
        score, evidence = integrated.get("competency_score"), integrated.get("evidence")
        if integrated.get("status") != "passed": errors.append("Integrated capstone has not passed")
        if not isinstance(score, int) or isinstance(score, bool) or score < 3: errors.append("Integrated capstone requires competency_score >= 3")
        if not isinstance(evidence, list) or not evidence: errors.append("Integrated capstone requires inspectable evidence")
    return errors

def report(data: Any) -> dict[str, Any]:
    errors = validate(data)
    assurance = data.get("independent_assurance", {}) if _record(data) else {}
    return {"result": "NOT_READY" if errors else "LEARNING_READINESS_EVIDENCE_COMPLETE", "errors": errors,
            "independent_assurance": assurance.get("status", "not_satisfied") if _record(assurance) else "not_satisfied",
            "production_authority": "not_granted",
            "note": "Evidence completeness is not an independent competence certificate and never grants production, generation, deployment or publishing authority."}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try: data = json.loads(args.ledger.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INVALID_LEDGER: {exc}"); return 2
    result = report(data)
    if args.json: print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["result"])
        for error in result["errors"]: print(f"- {error}")
        print(f"Independent assurance: {result['independent_assurance']}")
        print("Production authority: not granted")
    return 0 if not result["errors"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
