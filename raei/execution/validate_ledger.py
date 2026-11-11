#!/usr/bin/env python3
"""Validate the RAEI evidence ledger. Standard library only; does not certify competence."""
import json
import sys
from pathlib import Path

VALID_STATUSES = {"not_started", "in_progress", "needs_correction", "passed", "blocked"}

def main(path: str) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = []
    domains = data.get("domains", {})
    required_domains = {"engineering", "whole_bible", "bible_only_ethics", "rhemascript", "integrated_capstone"}
    missing = required_domains - set(domains)
    if missing:
        errors.append(f"Missing domains: {', '.join(sorted(missing))}")

    for name, domain in domains.items():
        status = domain.get("status")
        if status not in VALID_STATUSES:
            errors.append(f"{name}: invalid status {status!r}")
        if status == "passed" and not domain.get("evidence"):
            errors.append(f"{name}: cannot be passed without evidence")

    eng = domains.get("engineering", {})
    eng_evidence = {x.get("id") for x in eng.get("evidence", []) if x.get("status") == "verified"}
    for item in eng.get("required_capstones", []):
        if item not in eng_evidence:
            errors.append(f"Engineering capstone not verified: {item}")

    bible = domains.get("whole_bible", {})
    passed_books = {x.get("book_id") for x in bible.get("books", []) if x.get("status") == "passed" and x.get("evidence")}
    if len(passed_books) < int(bible.get("required_book_count", 66)):
        errors.append(f"Bible study incomplete: {len(passed_books)}/{bible.get('required_book_count', 66)} books passed")

    ethics = domains.get("bible_only_ethics", {})
    passed_cases = {x.get("case_id") for x in ethics.get("cases", []) if x.get("status") == "passed" and x.get("evidence")}
    if len(passed_cases) < int(ethics.get("required_case_count", 12)):
        errors.append(f"Ethics cases incomplete: {len(passed_cases)}/{ethics.get('required_case_count', 12)} passed")

    rs = domains.get("rhemascript", {})
    passed_caps = {x.get("capability_id") for x in rs.get("capabilities", []) if x.get("status") == "passed" and x.get("evidence")}
    missing_caps = set(rs.get("required_capability_ids", [])) - passed_caps
    if missing_caps:
        errors.append(f"RhemaScript capabilities not evidenced: {len(missing_caps)} outstanding")

    integrated = domains.get("integrated_capstone", {})
    if integrated.get("status") != "passed" or not integrated.get("evidence"):
        errors.append("Integrated capstone has not passed with evidence")
    if integrated.get("critical_failure"):
        errors.append("Integrated capstone has a critical failure")
    if data.get("independent_assurance", {}).get("status") != "satisfied":
        errors.append("Independent assurance is outstanding")
    if data.get("production_authority") != "granted":
        errors.append("Production authority has not been separately granted")

    if errors:
        print("NOT READY — evidence validation failed")
        for error in errors:
            print(f"- {error}")
        return 1
    print("EVIDENCE GATES SATISFIED — this is not, by itself, a grant of authority.")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_ledger.py ledger.json")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
