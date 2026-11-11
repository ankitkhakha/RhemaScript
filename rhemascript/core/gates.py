"""Fail-closed project gate progression for the RhemaScript NEW SYSTEM.

This module records gate decisions; it does not impersonate the Human Director
or grant execution/publishing authority. Callers must supply explicit evidence
references and actor identifiers for every decision.
"""
from dataclasses import dataclass
from enum import Enum
from rhemascript.registry.system_registry import REQUIRED_GATES

class GateError(PermissionError):
    """Raised when a project attempts an invalid or unsupported gate action."""

class GateDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    RETURNED = "RETURNED"

@dataclass(frozen=True)
class GateRecord:
    project_id: str
    gate: str
    decision: GateDecision
    actor_id: str
    evidence_ref: str

    def __post_init__(self):
        for field in ("project_id", "actor_id", "evidence_ref"):
            if not isinstance(getattr(self, field), str) or not getattr(self, field).strip():
                raise GateError(f"{field} must be a non-empty string")
        if self.gate not in REQUIRED_GATES:
            raise GateError(f"unknown approval gate: {self.gate}")
        if not isinstance(self.decision, GateDecision):
            raise GateError("decision must use a supported GateDecision")

@dataclass(frozen=True)
class ProjectGateState:
    project_id: str
    records: tuple[GateRecord, ...] = ()

    def record(self, item: GateRecord) -> "ProjectGateState":
        if item.project_id != self.project_id:
            raise GateError("gate record project_id does not match state")
        expected_index = len(self.records)
        if expected_index >= len(REQUIRED_GATES):
            raise GateError("all approval gates are already recorded")
        expected_gate = REQUIRED_GATES[expected_index]
        if item.gate != expected_gate:
            raise GateError(f"expected gate {expected_gate}; received {item.gate}")
        if item.decision is not GateDecision.APPROVED:
            raise GateError(f"gate {item.gate} is {item.decision.value}; progression blocked")
        return ProjectGateState(self.project_id, self.records + (item,))

    @property
    def next_gate(self) -> str | None:
        if len(self.records) >= len(REQUIRED_GATES):
            return None
        return REQUIRED_GATES[len(self.records)]

    @property
    def all_gates_approved(self) -> bool:
        return len(self.records) == len(REQUIRED_GATES)

def authorise_generation(*, generation_authorisation: bool, gate_state: ProjectGateState) -> bool:
    """Require both all six recorded approvals and separate explicit authority."""
    if not gate_state.all_gates_approved:
        raise GateError("generation requires all six approval gates to be approved")
    if generation_authorisation is not True:
        raise GateError("generation requires separate explicit execution authorisation")
    return True
