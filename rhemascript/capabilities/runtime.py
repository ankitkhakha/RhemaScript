"""Capability orchestration with specialist, evidence-bound assessments."""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from rhemascript.registry.system_registry import CAPABILITIES
from rhemascript.core.envelope import validate_record, ContractError
from .specialists import assess_specialist, SpecialistInputError

class CapabilityError(ValueError): pass

@dataclass(frozen=True)
class CapabilityResult:
    capability_id: str
    project_id: str
    status: str
    outputs: dict[str, Any]
    missing_evidence: tuple[str, ...] = ()

EVIDENCE_REQUIREMENTS = {
 'CAP-01': ('sources',),
 'CAP-02': ('passage_context','interpretive_claims'),
 'CAP-03': ('script_elements','source_mapping'),
 'CAP-04': ('dimension_scores','eligibility_gates'),
 'CAP-05': ('beats','narrative_constraints'),
 'CAP-06': ('observations','measurement_window'),
 'CAP-07': ('visual_reference_set','shot_observations'),
 'CAP-08': ('shot_plan','runtime_budget_seconds','asset_inventory'),
 'CAP-09': ('target_platform','verified_tool_evidence'),
 'CAP-10': ('asset_manifest','rights_provenance'),
 'CAP-11': ('quality_dimensions','hard_stop_findings'),
 'CAP-12': ('threats','control_evidence'),
 'CAP-13': ('rights_basis','provenance_chain'),
 'CAP-14': ('failure_record','reproduction_or_observation'),
 'CAP-15': ('performance_observations','linked_production_version'),
}

class CapabilityEngine:
    def __init__(self):
        self.registry = dict(CAPABILITIES)

    def execute(self, capability_id: str, record: dict[str, Any], *, actor_role: str,
                evidence: dict[str, Any], authority: dict[str, bool] | None = None) -> CapabilityResult:
        if capability_id not in self.registry:
            raise CapabilityError(f'unknown capability: {capability_id}')
        try:
            validate_record(record)
        except ContractError as exc:
            raise CapabilityError(str(exc)) from exc
        if not isinstance(actor_role,str) or not actor_role.strip():
            raise CapabilityError('actor_role is required')
        if not isinstance(evidence,dict):
            raise CapabilityError('evidence must be an object')
        required=EVIDENCE_REQUIREMENTS[capability_id]
        missing=tuple(k for k in required if k not in evidence or evidence[k] is None or evidence[k]=='' or evidence[k]==[] or evidence[k]=={})
        outputs={'capability_name':self.registry[capability_id],
                 'evidence_keys_received':sorted(evidence),
                 'actor_role':actor_role,
                 'evaluated_at':datetime.now(timezone.utc).isoformat(),
                 'assessment_boundary':'bounded rule-based assessment; expert and human decision authority retained'}
        if missing:
            return CapabilityResult(capability_id,record['project_id'],'NOT_ASSESSED',outputs,missing)
        try:
            outputs['specialist_assessment']=assess_specialist(capability_id,evidence)
        except SpecialistInputError as exc:
            raise CapabilityError(str(exc)) from exc
        return CapabilityResult(capability_id,record['project_id'],'READY_FOR_HUMAN_REVIEW',outputs,())
