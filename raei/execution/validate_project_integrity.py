"""Fail-closed validator for a RhemaScript project-readiness record.

This checks traceability and authority separation only. It does not approve,
generate, publish, deploy, or grant production authority.
"""
from __future__ import annotations

from typing import Any

CHAIN = (
    "biblical_source",
    "approved_script",
    "approved_narration",
    "storyboard",
    "audio_visual_plan",
    "clip_prompt",
    "asset",
    "edited_film",
)

GATES = (
    "project_creative_direction",
    "script_biblical_accuracy",
    "visual_development",
    "production_plan_prompt",
    "generation_authorisation",
    "final_film",
)

AUTHORITY_FIELDS = (
    "generation_authorisation",
    "publishing_authorisation",
    "deployment_authorisation",
    "merge_authorisation",
)


def _nonempty_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_project(record: Any) -> list[str]:
    """Return all integrity blockers; malformed input fails closed."""
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["project record must be an object"]

    if record.get("record_type") != "rhemascript_project_readiness":
        errors.append("record_type must be rhemascript_project_readiness")

    chain = record.get("source_to_final_chain")
    if not isinstance(chain, list):
        errors.append("source_to_final_chain must be a list")
        chain = []

    seen: set[str] = set()
    positions: dict[str, int] = {}
    for index, item in enumerate(chain):
        if not isinstance(item, dict):
            errors.append(f"chain item {index} must be an object")
            continue
        stage = item.get("stage")
        if not isinstance(stage, str) or not stage.strip() or stage != stage.strip():
            errors.append(f"chain item {index} has no valid stage identifier")
            continue
        if stage not in CHAIN:
            errors.append(f"unknown chain stage: {stage}")
            continue
        if stage in seen:
            errors.append(f"duplicate chain stage: {stage}")
        seen.add(stage)
        positions[stage] = index
        if not _nonempty_ref(item.get("evidence_ref")):
            errors.append(f"{stage} is missing evidence_ref")
        if item.get("status") != "present":
            errors.append(f"{stage} status must be present")

    for stage in CHAIN:
        if stage not in seen:
            errors.append(f"missing chain stage: {stage}")
    ordered = [positions[s] for s in CHAIN if s in positions]
    if len(ordered) == len(CHAIN) and ordered != sorted(ordered):
        errors.append("source-to-final chain is out of canonical order")

    gates = record.get("approval_gates")
    if not isinstance(gates, list):
        errors.append("approval_gates must be a list")
        gates = []
    gate_positions: dict[str, int] = {}
    gate_seen: set[str] = set()
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            errors.append(f"approval gate {index} must be an object")
            continue
        gate_id = gate.get("gate")
        if not isinstance(gate_id, str) or not gate_id.strip() or gate_id != gate_id.strip():
            errors.append(f"approval gate {index} has no valid gate identifier")
            continue
        if gate_id not in GATES:
            errors.append(f"unknown approval gate: {gate_id}")
            continue
        if gate_id in gate_seen:
            errors.append(f"duplicate approval gate: {gate_id}")
        gate_seen.add(gate_id)
        gate_positions[gate_id] = index
        if gate.get("decision") != "approved":
            errors.append(f"{gate_id} is not approved")
        if not _nonempty_ref(gate.get("approval_evidence_ref")):
            errors.append(f"{gate_id} is missing approval evidence")
        if not _nonempty_ref(gate.get("approver")):
            errors.append(f"{gate_id} is missing approver identity")
    for gate_id in GATES:
        if gate_id not in gate_seen:
            errors.append(f"missing approval gate: {gate_id}")
    ordered_gates = [gate_positions[g] for g in GATES if g in gate_positions]
    if len(ordered_gates) == len(GATES) and ordered_gates != sorted(ordered_gates):
        errors.append("approval gates are out of canonical order")

    authorities = record.get("authorities")
    if not isinstance(authorities, dict):
        errors.append("authorities must be an object")
        authorities = {}
    for field in AUTHORITY_FIELDS:
        decision = authorities.get(field)
        if not isinstance(decision, str) or decision not in ("not_authorised", "authorised"):
            errors.append(f"{field} must be explicitly not_authorised or authorised")

    # This validator is a readiness check, not an execution switch.
    if record.get("generation_executed") is not False:
        errors.append("generation_executed must be false for this non-production validation")
    if record.get("publishing_executed") is not False:
        errors.append("publishing_executed must be false for this non-production validation")
    if record.get("production_authority") != "not_granted":
        errors.append("production_authority must remain not_granted")

    return errors


def readiness_report(record: Any) -> dict[str, Any]:
    blockers = validate_project(record)
    return {
        "result": "PROJECT_TRACEABILITY_COMPLETE" if not blockers else "BLOCKED",
        "blockers": blockers,
        "generation_executed": False if not isinstance(record, dict) else record.get("generation_executed"),
        "publishing_executed": False if not isinstance(record, dict) else record.get("publishing_executed"),
        "production_authority": "not_granted" if not isinstance(record, dict) else record.get("production_authority"),
        "note": "Traceability validation only; not an approval or production-authority grant.",
    }
