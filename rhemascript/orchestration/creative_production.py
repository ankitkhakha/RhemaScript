"""Human-governed creative-production orchestration for RhemaScript.

The orchestrator sequences existing CAP-01..CAP-15 assessments and reports
missing dependencies. It does not approve gates, generate media, call providers,
write externally, publish, or replace the Human Director.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from rhemascript.capabilities.runtime import CapabilityEngine, CapabilityResult
from rhemascript.core.envelope import validate_record
from rhemascript.core.gates import GateDecision, GateError, GateRecord, ProjectGateState
from rhemascript.registry.system_registry import REQUIRED_GATES


CAPABILITY_ORDER = (
    "CAP-01", "CAP-02", "CAP-03", "CAP-04", "CAP-05", "CAP-07",
    "CAP-12", "CAP-09", "CAP-13", "CAP-10", "CAP-08", "CAP-11",
    "CAP-06", "CAP-14", "CAP-15",
)

DEPENDENCIES = {
    "CAP-01": (),
    "CAP-02": ("CAP-01",),
    "CAP-03": ("CAP-01", "CAP-02"),
    "CAP-04": ("CAP-01",),
    "CAP-05": ("CAP-02", "CAP-03", "CAP-04"),
    "CAP-06": (),
    "CAP-07": ("CAP-05",),
    "CAP-08": ("CAP-05", "CAP-07", "CAP-09", "CAP-10", "CAP-12", "CAP-13"),
    "CAP-09": ("CAP-12",),
    "CAP-10": ("CAP-13",),
    "CAP-11": ("CAP-08", "CAP-10", "CAP-13"),
    "CAP-12": (),
    "CAP-13": (),
    "CAP-14": (),
    "CAP-15": ("CAP-11",),
}

PHASES = (
    ("SOURCE_AND_RESEARCH", ("CAP-01", "CAP-02", "CAP-04")),
    ("SCRIPT_INTEGRITY", ("CAP-03",)),
    ("CREATIVE_DEVELOPMENT", ("CAP-05",)),
    ("VISUAL_DEVELOPMENT", ("CAP-07",)),
    ("SECURITY_AND_TOOL_PREFLIGHT", ("CAP-12", "CAP-09")),
    ("ASSET_AND_RIGHTS_READINESS", ("CAP-13", "CAP-10")),
    ("PRODUCTION_PLANNING", ("CAP-08",)),
    ("FINAL_QUALITY_CONTROL", ("CAP-11",)),
    ("LEARNING_AND_FAILURE", ("CAP-06", "CAP-14", "CAP-15")),
)

OPTIONAL_CAPABILITIES = frozenset(("CAP-06", "CAP-14", "CAP-15"))
REQUIRED_GENERATION_CAPABILITIES = (
    "CAP-01", "CAP-02", "CAP-03", "CAP-05", "CAP-07", "CAP-08",
    "CAP-09", "CAP-10", "CAP-11", "CAP-12", "CAP-13",
)


class OrchestrationError(ValueError):
    """Raised for malformed orchestration input."""


@dataclass(frozen=True)
class OrchestrationResult:
    project_id: str
    run_id: str
    status: str
    capability_results: dict[str, dict[str, Any]]
    phase_results: tuple[dict[str, Any], ...]
    gate_status: dict[str, Any]
    blocked_dependencies: tuple[dict[str, Any], ...]
    audit_trace: tuple[dict[str, Any], ...]
    generation_preconditions_met: bool
    generation_action_performed: bool = False
    external_action_performed: bool = False
    publishing_performed: bool = False


class CreativeProductionOrchestrator:
    """Coordinates existing specialist assessments without taking approval authority."""

    def __init__(self, capability_engine: CapabilityEngine | None = None):
        self.engine = capability_engine or CapabilityEngine()

    @staticmethod
    def _gate_state(project_id: str, gate_records: list[dict[str, Any]]) -> tuple[ProjectGateState, dict[str, Any]]:
        state = ProjectGateState(project_id)
        findings: list[dict[str, Any]] = []
        for index, raw in enumerate(gate_records):
            if not isinstance(raw, dict):
                findings.append({"index": index, "reason": "GATE_RECORD_MUST_BE_OBJECT"})
                break
            try:
                decision = GateDecision(raw.get("decision"))
                item = GateRecord(
                    project_id=raw.get("project_id", ""),
                    gate=raw.get("gate", ""),
                    decision=decision,
                    actor_id=raw.get("actor_id", ""),
                    evidence_ref=raw.get("evidence_ref", ""),
                )
                state = state.record(item)
            except (ValueError, GateError) as exc:
                findings.append({"index": index, "reason": str(exc)})
                break
        return state, {
            "approved_gate_count": len(state.records),
            "required_gate_count": len(REQUIRED_GATES),
            "next_required_gate": state.next_gate,
            "all_gates_approved": state.all_gates_approved,
            "gate_findings": findings,
            "gate_status": "BLOCKED" if findings else (
                "ALL_APPROVED" if state.all_gates_approved else "AWAITING_HUMAN_APPROVAL"
            ),
            "required_gate_sequence": list(REQUIRED_GATES),
        }

    def run(
        self,
        project_record: dict[str, Any],
        *,
        capability_evidence: dict[str, dict[str, Any]],
        actor_role: str,
        gate_records: list[dict[str, Any]] | None = None,
        generation_authorisation: bool = False,
        run_id: str | None = None,
    ) -> OrchestrationResult:
        """Assess project evidence in dependency order; never executes production actions."""
        validate_record(project_record)
        if not isinstance(actor_role, str) or not actor_role.strip():
            raise OrchestrationError("actor_role is required")
        if not isinstance(capability_evidence, dict):
            raise OrchestrationError("capability_evidence must be an object keyed by capability ID")
        if not isinstance(generation_authorisation, bool):
            raise OrchestrationError("generation_authorisation must be boolean")
        if gate_records is None:
            gate_records = []
        if not isinstance(gate_records, list):
            raise OrchestrationError("gate_records must be a list")

        project_id = project_record["project_id"]
        resolved_run_id = run_id or f"{project_id}:{project_record['version']}:{datetime.now(timezone.utc).isoformat()}"
        gate_state, gate_status = self._gate_state(project_id, gate_records)

        results: dict[str, dict[str, Any]] = {}
        blocked: list[dict[str, Any]] = []
        audit: list[dict[str, Any]] = []

        for capability_id in CAPABILITY_ORDER:
            evidence = capability_evidence.get(capability_id, {})
            if not isinstance(evidence, dict):
                raise OrchestrationError(f"{capability_id} evidence must be an object")

            unmet = [
                dependency for dependency in DEPENDENCIES[capability_id]
                if results.get(dependency, {}).get("status") != "ASSESSED_FOR_HUMAN_REVIEW"
            ]
            if unmet:
                row = {
                    "capability_id": capability_id,
                    "status": "BLOCKED_DEPENDENCY",
                    "missing_dependencies": unmet,
                    "missing_evidence": [],
                    "reason": "upstream capability evidence has not been assessed",
                }
                results[capability_id] = row
                blocked.append(row)
            elif capability_id in OPTIONAL_CAPABILITIES and not evidence:
                row = {
                    "capability_id": capability_id,
                    "status": "NOT_ASSESSED_OPTIONAL",
                    "missing_dependencies": [],
                    "missing_evidence": [],
                    "reason": "optional learning/incident evidence was not supplied",
                }
                results[capability_id] = row
            else:
                result: CapabilityResult = self.engine.execute(
                    capability_id,
                    project_record,
                    actor_role=actor_role,
                    evidence=evidence,
                )
                status = "NOT_ASSESSED" if result.status == "NOT_ASSESSED" else "ASSESSED_FOR_HUMAN_REVIEW"
                row = {
                    "capability_id": capability_id,
                    "status": status,
                    "missing_dependencies": [],
                    "missing_evidence": list(result.missing_evidence),
                    "outputs": result.outputs,
                    "assessment_is_approval": False,
                }
                results[capability_id] = row
                if status == "NOT_ASSESSED":
                    blocked.append({
                        "capability_id": capability_id,
                        "status": status,
                        "missing_dependencies": [],
                        "missing_evidence": list(result.missing_evidence),
                        "reason": "required capability evidence is missing",
                    })

            refs = evidence.get("evidence_refs", [])
            if not isinstance(refs, list):
                refs = []
            audit.append({
                "run_id": resolved_run_id,
                "project_id": project_id,
                "project_version": project_record["version"],
                "capability_id": capability_id,
                "status": results[capability_id]["status"],
                "evidence_refs": refs,
                "actor_role": actor_role,
            })

        phase_results = []
        for phase_name, capability_ids in PHASES:
            statuses = [results[cid]["status"] for cid in capability_ids]
            phase_status = (
                "BLOCKED" if any(s == "BLOCKED_DEPENDENCY" for s in statuses)
                else "EVIDENCE_MISSING" if any(s == "NOT_ASSESSED" for s in statuses)
                else "OPTIONAL_EVIDENCE_NOT_SUPPLIED" if any(s == "NOT_ASSESSED_OPTIONAL" for s in statuses)
                else "ASSESSED_FOR_HUMAN_REVIEW"
            )
            phase_results.append({
                "phase": phase_name,
                "status": phase_status,
                "capabilities": list(capability_ids),
            })

        missing_generation_capabilities = [
            cid for cid in REQUIRED_GENERATION_CAPABILITIES
            if results.get(cid, {}).get("status") != "ASSESSED_FOR_HUMAN_REVIEW"
        ]
        critical_assessments_complete = not missing_generation_capabilities
        preconditions = (
            gate_state.all_gates_approved
            and generation_authorisation is True
            and critical_assessments_complete
        )
        if gate_status["gate_status"] == "BLOCKED":
            overall = "GOVERNANCE_BLOCKED"
        elif any(row["status"] in ("NOT_ASSESSED", "BLOCKED_DEPENDENCY") for row in results.values()):
            overall = "EVIDENCE_OR_DEPENDENCY_GAPS"
        else:
            overall = "ASSESSMENTS_READY_FOR_HUMAN_REVIEW"

        return OrchestrationResult(
            project_id=project_id,
            run_id=resolved_run_id,
            status=overall,
            capability_results=results,
            phase_results=tuple(phase_results),
            gate_status={
                **gate_status,
                "separate_generation_authorisation_present": generation_authorisation,
                "required_generation_capabilities_complete": critical_assessments_complete,
                "missing_generation_capabilities": missing_generation_capabilities,
                "generation_preconditions_met": preconditions,
            },
            blocked_dependencies=tuple(blocked),
            audit_trace=tuple(audit),
            generation_preconditions_met=preconditions,
        )
