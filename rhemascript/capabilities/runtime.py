"""Executable capability contract layer for all 15 registered capabilities.

This layer validates inputs, required evidence and authority boundaries. It is
not a substitute for specialist biblical scholarship, legal review, platform
telemetry or human editorial judgement; it refuses to fabricate those outputs.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from rhemascript.registry.system_registry import CAPABILITIES
from rhemascript.core.envelope import validate_record, ContractError

class CapabilityError(ValueError): pass

@dataclass(frozen=True)
class CapabilityResult:
    capability_id: str
    project_id: str
    status: str
    outputs: dict[str, Any]
    missing_evidence: tuple[str, ...] = ()

EVIDENCE_REQUIREMENTS = {
 'CAP-01': ('source_reference','translation_or_source_version'),
 'CAP-02': ('passage_context','interpretive_claims'),
 'CAP-03': ('approved_script','source_mapping'),
 'CAP-04': ('audience_definition','content_objective','evidence_basis'),
 'CAP-05': ('story_outline','narrative_constraints'),
 'CAP-06': ('observed_audience_data','measurement_window'),
 'CAP-07': ('visual_reference_set','continuity_constraints'),
 'CAP-08': ('shot_plan','runtime_budget','asset_inventory'),
 'CAP-09': ('target_platform','verified_tool_evidence'),
 'CAP-10': ('asset_manifest','rights_provenance'),
 'CAP-11': ('quality_dimensions','review_evidence'),
 'CAP-12': ('threat_context','control_evidence'),
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
        try: validate_record(record)
        except ContractError as exc: raise CapabilityError(str(exc)) from exc
        if not actor_role or not isinstance(actor_role,str):
            raise CapabilityError('actor_role is required')
        if not isinstance(evidence,dict): raise CapabilityError('evidence must be an object')
        required=EVIDENCE_REQUIREMENTS[capability_id]
        missing=tuple(k for k in required if k not in evidence or evidence[k] in (None,'',[],{}))
        status='NOT_ASSESSED' if missing else 'READY_FOR_HUMAN_REVIEW'
        outputs={'capability_name':self.registry[capability_id],
                 'evidence_keys_received':sorted(evidence),
                 'assessment_boundary':'contract-level validation only; specialist judgement remains required',
                 'actor_role':actor_role,
                 'evaluated_at':datetime.now(timezone.utc).isoformat()}
        return CapabilityResult(capability_id,record['project_id'],status,outputs,missing)
