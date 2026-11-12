"""Structured lesson, practice, rubric and correction workflow for RAEI."""
from __future__ import annotations
from .ledger import LedgerError, append_event, now

def create_lesson(data, unit_id, objectives, source_refs, practice_prompt, rubric):
    if unit_id not in data["units"]:
        raise LedgerError(f"unknown unit: {unit_id}")
    if not objectives or not source_refs or not practice_prompt or not rubric:
        raise LedgerError("lesson requires objectives, source references, practice and rubric")
    unit = data["units"][unit_id]
    if unit["status"] == "passed":
        raise LedgerError("passed units are immutable; create a versioned unit to extend learning")
    if unit.get("lesson") is not None:
        raise LedgerError("lesson already exists; create a versioned unit to revise it")
    unit["lesson"] = {"objectives": objectives, "source_refs": source_refs,
                      "practice_prompt": practice_prompt, "rubric": rubric, "created_at": now()}
    append_event(data, "lesson_created", unit_id, {"objectives": objectives, "source_refs": source_refs})

def record_practice(data, unit_id, artifact_ref, method, result, status="verified"):
    if unit_id not in data["units"]:
        raise LedgerError(f"unknown unit: {unit_id}")
    if data["units"][unit_id]["status"] == "passed":
        raise LedgerError("passed units are immutable; create a versioned unit for further practice")
    unit = data["units"][unit_id]
    if unit.get("lesson") is None and not all(
        unit.get(key) for key in ("objectives", "source_refs", "practice_prompt", "rubric")
    ):
        raise LedgerError("cannot record practice before lesson or seeded curriculum is defined")
    if not all(isinstance(value, str) and value.strip() for value in (artifact_ref, method, result)):
        raise LedgerError("practice requires artifact reference, method and result")
    if status not in {"verified", "reported_unverified", "planned"}:
        raise LedgerError("invalid practice evidence status")
    unit=data["units"][unit_id]
    unit.setdefault("practice", []).append({"artifact_ref":artifact_ref,"method":method,
        "result":result,"status":status,"recorded_at":now()})
    if unit["status"] != "passed":
        unit["status"]="in_progress"
    append_event(data,"practice_recorded",unit_id,{"artifact_ref":artifact_ref,"method":method,"result":result,"status":status})

def record_rubric_assessment(data, unit_id, criterion_scores, evidence_ref, evidence_status, assessor_note=""):
    if unit_id not in data["units"]:
        raise LedgerError(f"unknown unit: {unit_id}")
    unit=data["units"][unit_id]
    if unit["status"] == "passed":
        raise LedgerError("passed units are immutable; create a versioned unit for reassessment")
    lesson = unit.get("lesson")
    rubric = lesson["rubric"] if lesson is not None else unit.get("rubric")
    if not rubric:
        raise LedgerError("lesson or seeded curriculum rubric must exist before assessment")
    if not isinstance(criterion_scores, dict):
        raise LedgerError("criterion scores must be an object mapping rubric criteria to scores")
    if not isinstance(evidence_status, str) or evidence_status not in {"verified", "reported_unverified", "planned"}:
        raise LedgerError("invalid evidence status")
    if set(criterion_scores) != set(rubric):
        raise LedgerError("criterion scores must match every rubric criterion exactly")
    if any(not isinstance(score,int) or isinstance(score,bool) or not 0 <= score <= 4 for score in criterion_scores.values()):
        raise LedgerError("each criterion score must be an integer from 0 to 4")
    if evidence_status == "verified" and (not isinstance(evidence_ref, str) or not evidence_ref.strip()):
        raise LedgerError("verified assessment requires an evidence reference")
    if not any(p["status"]=="verified" for p in unit.get("practice",[])):
        raise LedgerError("at least one verified practice record is required")
    if any(data["units"][p]["status"] != "passed" for p in unit["prerequisites"]):
        raise LedgerError("cannot assess before prerequisites pass")
    score=min(criterion_scores.values()) if criterion_scores else 0
    passed=score >= 3 and evidence_status=="verified"
    unit.update({"status":"passed" if passed else "needs_correction","score":score,
                 "criterion_scores":criterion_scores,"evidence_ref":evidence_ref,
                 "evidence_status":evidence_status,"assessor_note":assessor_note})
    append_event(data,"rubric_assessment_recorded",unit_id,{"criterion_scores":criterion_scores,
        "evidence_ref":evidence_ref,"evidence_status":evidence_status,"result":unit["status"],
        "assessor_note":assessor_note})

def record_correction(data, unit_id, correction_note, new_artifact_ref, method, result):
    if unit_id not in data["units"]:
        raise LedgerError(f"unknown unit: {unit_id}")
    unit=data["units"][unit_id]
    if unit["status"] not in {"needs_correction","in_progress"}:
        raise LedgerError("correction is only allowed for incomplete or failed units")
    if not all(isinstance(value, str) and value.strip() for value in
               (correction_note, new_artifact_ref, method, result)):
        raise LedgerError("correction requires explanation, new artefact, method and result")
    unit.setdefault("corrections",[]).append({"note":correction_note,"artifact_ref":new_artifact_ref,
        "method":method,"result":result,"recorded_at":now()})
    unit["status"]="in_progress"
    append_event(data,"correction_recorded",unit_id,{"note":correction_note,"artifact_ref":new_artifact_ref,
        "method":method,"result":result})
