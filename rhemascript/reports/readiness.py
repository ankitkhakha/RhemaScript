"""Read-only project readiness summaries derived from orchestration results."""
from __future__ import annotations

from typing import Any

from rhemascript.orchestration.creative_production import OrchestrationResult


def build_readiness_report(result: OrchestrationResult) -> dict[str, Any]:
    """Build a deterministic report; never upgrades assessment into approval."""
    if not isinstance(result, OrchestrationResult):
        raise TypeError("result must be an OrchestrationResult")

    capability_rows = []
    blockers = []
    optional_gaps = []
    for capability_id, row in result.capability_results.items():
        status = row.get("status", "UNKNOWN")
        item = {
            "capability_id": capability_id,
            "status": status,
            "missing_evidence": list(row.get("missing_evidence", [])),
            "missing_dependencies": list(row.get("missing_dependencies", [])),
            "assessment_is_approval": False,
        }
        capability_rows.append(item)
        if status in {"NOT_ASSESSED", "BLOCKED_DEPENDENCY"}:
            blockers.append({
                "capability_id": capability_id,
                "status": status,
                "reason": row.get("reason", "capability evidence or upstream dependency is missing"),
                "missing_evidence": item["missing_evidence"],
                "missing_dependencies": item["missing_dependencies"],
            })
        elif status == "NOT_ASSESSED_OPTIONAL":
            optional_gaps.append({
                "capability_id": capability_id,
                "reason": row.get("reason", "optional evidence was not supplied"),
            })

    gate = result.gate_status
    return {
        "project_id": result.project_id,
        "run_id": result.run_id,
        "overall_status": result.status,
        "capability_assessments": capability_rows,
        "blockers": blockers,
        "optional_evidence_gaps": optional_gaps,
        "governance": {
            "status": gate.get("gate_status", "UNKNOWN"),
            "approved_gate_count": gate.get("approved_gate_count", 0),
            "required_gate_count": gate.get("required_gate_count", 0),
            "next_required_gate": gate.get("next_required_gate"),
            "all_gates_approved": bool(gate.get("all_gates_approved", False)),
            "findings": list(gate.get("gate_findings", [])),
            "separate_generation_authorisation_present": bool(
                gate.get("separate_generation_authorisation_present", False)
            ),
            "missing_generation_capabilities": list(
                gate.get("missing_generation_capabilities", [])
            ),
        },
        "generation_preconditions_met": result.generation_preconditions_met,
        "execution": {
            "generation_performed": result.generation_action_performed,
            "external_action_performed": result.external_action_performed,
            "publishing_performed": result.publishing_performed,
            "assessment_is_execution_authorisation": False,
        },
        "interpretation": (
            "Preconditions met; this report does not execute or authorise generation."
            if result.generation_preconditions_met
            else "Not ready; resolve listed evidence, dependency and governance gaps."
        ),
    }


def run_project_assessment(
    pack: dict[str, Any],
    *,
    actor_role: str,
    generation_authorisation: bool = False,
    run_id: str | None = None,
    orchestrator: Any = None,
) -> tuple[Any, OrchestrationResult, dict[str, Any]]:
    """Validate a project pack, assess it, and return its read-only readiness report."""
    from rhemascript.evidence import run_evidence_pack

    validated, result = run_evidence_pack(
        pack,
        actor_role=actor_role,
        generation_authorisation=generation_authorisation,
        run_id=run_id,
        orchestrator=orchestrator,
    )
    return validated, result, build_readiness_report(result)
