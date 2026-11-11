"""Deterministic, evidence-bound specialist assessments for the 15 RhemaScript capabilities.

These functions perform bounded rule-based checks over caller-supplied evidence.
They do not fetch sources, infer missing facts, replace expert review, or perform
external actions. Missing/ambiguous evidence is reported rather than fabricated.
"""
from __future__ import annotations
from typing import Any
import math
from .tool_registry import assess_tool_preflight

class SpecialistInputError(ValueError):
    """Raised when supplied specialist evidence has an invalid shape."""

def _obj(e: dict, key: str) -> dict:
    value = e.get(key)
    if not isinstance(value, dict):
        raise SpecialistInputError(f"{key} must be an object")
    return value

def _seq(e: dict, key: str) -> list:
    value = e.get(key)
    if not isinstance(value, list):
        raise SpecialistInputError(f"{key} must be a list")
    return value

def _nonempty(e: dict, key: str) -> Any:
    value=e.get(key)
    if value is None or value == "" or value == [] or value == {}:
        raise SpecialistInputError(f"{key} must be non-empty")
    return value

def _score(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int,float)) or not math.isfinite(value) or not 0 <= value <= 100:
        raise SpecialistInputError(f"{name} must be a finite number from 0 to 100")
    return float(value)

def _cap01(e):
    sources=_seq(e,"sources")
    ids=[s.get("source_id") for s in sources if isinstance(s,dict)]
    duplicates=sorted({x for x in ids if ids.count(x)>1})
    missing=[i for i,s in enumerate(sources) if not isinstance(s,dict) or not s.get("source_id") or not s.get("reference") or not s.get("version")]
    return {"source_count":len(sources),"duplicate_source_ids":duplicates,"incomplete_source_indexes":missing,
            "provenance_status":"INCOMPLETE" if missing or duplicates else "STRUCTURALLY_COMPLETE",
            "truth_claim":"not assessed; source identity and provenance structure only"}

def _cap02(e):
    context=_nonempty(e,"passage_context")
    claims=_seq(e,"interpretive_claims")
    findings=[]
    for i,c in enumerate(claims):
        if not isinstance(c,dict): raise SpecialistInputError("each interpretive_claim must be an object")
        flags=[]
        if not c.get("supporting_evidence"): flags.append("NO_SUPPORTING_EVIDENCE")
        if not c.get("literary_context_reviewed",False): flags.append("LITERARY_CONTEXT_NOT_REVIEWED")
        if not c.get("historical_context_reviewed",False): flags.append("HISTORICAL_CONTEXT_NOT_REVIEWED")
        if c.get("certainty")=="ABSOLUTE" and not c.get("explicit_textual_basis"): flags.append("OVERSTATED_CERTAINTY")
        findings.append({"claim_index":i,"flags":flags,"review_required":bool(flags)})
    return {"passage_context_supplied":bool(context),"claim_reviews":findings,
            "overall_status":"REVIEW_REQUIRED" if any(x["review_required"] for x in findings) else "NO_STRUCTURAL_FLAGS",
            "authority_boundary":"flags are prompts for qualified human biblical review, not theological verdicts"}

def _cap03(e):
    script=_seq(e,"script_elements"); mapping=_seq(e,"source_mapping")
    mapped={m.get("element_id") for m in mapping if isinstance(m,dict) and m.get("element_id") and m.get("source_reference")}
    unsupported=[s.get("element_id",i) for i,s in enumerate(script) if not isinstance(s,dict) or s.get("element_id") not in mapped]
    invalid=[i for i,m in enumerate(mapping) if not isinstance(m,dict) or not m.get("source_reference") or not m.get("element_id")]
    return {"script_element_count":len(script),"mapped_element_count":len(script)-len(unsupported),
            "unmapped_elements":unsupported,"invalid_mapping_indexes":invalid,
            "integrity_status":"GAPS_FOUND" if unsupported or invalid else "MAPPING_COMPLETE",
            "note":"mapping completeness does not establish interpretive correctness"}

def _cap04(e):
    weights={"biblical_relevance":20,"audience_relevance":15,"content_value":15,"discovery_potential":10,
             "differentiation":10,"narrative_suitability":10,"production_feasibility":10,"strategic_alignment":10}
    scores=_obj(e,"dimension_scores")
    missing=sorted(set(weights)-set(scores))
    extra=sorted(set(scores)-set(weights))
    if missing or extra: raise SpecialistInputError(f"dimension_scores keys mismatch; missing={missing}, extra={extra}")
    total=sum(_score(scores[k],k)*w for k,w in weights.items())/100
    gates=_obj(e,"eligibility_gates")
    failed=sorted(k for k,v in gates.items() if v is not True)
    return {"weighted_score":round(total,2),"weights":weights,"failed_eligibility_gates":failed,
            "recommendation":"INELIGIBLE" if failed else ("PRIORITISE" if total>=75 else "CONSIDER" if total>=55 else "DEFER"),
            "score_is_not_a_prediction":True}

def _cap05(e):
    beats=_seq(e,"beats"); constraints=_obj(e,"narrative_constraints")
    ids=[b.get("beat_id") for b in beats if isinstance(b,dict)]
    missing=[i for i,b in enumerate(beats) if not isinstance(b,dict) or not b.get("purpose")]
    duplicate=sorted({x for x in ids if ids.count(x)>1})
    duration=e.get("target_duration_seconds")
    if duration is not None and (isinstance(duration,bool) or not isinstance(duration,(int,float)) or duration<=0):
        raise SpecialistInputError("target_duration_seconds must be positive")
    return {"beat_count":len(beats),"missing_purpose_indexes":missing,"duplicate_beat_ids":duplicate,
            "target_duration_seconds":duration,"constraints_supplied":sorted(constraints),
            "simulation_status":"STRUCTURAL_ISSUES" if missing or duplicate else "STRUCTURE_VALID_FOR_EDITORIAL_REVIEW"}

def _cap06(e):
    rows=_seq(e,"observations"); window=_nonempty(e,"measurement_window")
    if any(not isinstance(r,dict) or "metric" not in r or "value" not in r for r in rows):
        raise SpecialistInputError("each observation requires metric and value")
    return {"measurement_window":window,"observation_count":len(rows),"observations":rows,
            "causal_inference":"NOT_ESTABLISHED","recommendation":"compare only like-for-like cohorts and production versions"}

def _cap07(e):
    refs=_seq(e,"visual_reference_set"); shots=_seq(e,"shot_observations")
    refids={r.get("reference_id") for r in refs if isinstance(r,dict) and r.get("reference_id")}
    findings=[]
    for i,s in enumerate(shots):
        if not isinstance(s,dict): raise SpecialistInputError("each shot_observation must be an object")
        flags=[]
        if s.get("reference_id") not in refids: flags.append("REFERENCE_NOT_FOUND")
        if not s.get("continuity_observations"): flags.append("CONTINUITY_NOT_OBSERVED")
        findings.append({"shot_index":i,"flags":flags})
    return {"reference_count":len(refs),"shot_count":len(shots),"shot_findings":findings,
            "visual_assessment_boundary":"metadata/observations only; no image analysis performed"}

def _cap08(e):
    shots=_seq(e,"shot_plan"); budget=_score(e.get("runtime_budget_seconds"),"runtime_budget_seconds")
    durations=[]
    for i,s in enumerate(shots):
        if not isinstance(s,dict): raise SpecialistInputError("each shot must be an object")
        durations.append(_score(s.get("duration_seconds"),f"shot[{i}].duration_seconds"))
    total=sum(durations)
    assets=_seq(e,"asset_inventory")
    missing=[s.get("required_asset_id") for s in shots if s.get("required_asset_id") and s.get("required_asset_id") not in {a.get("asset_id") for a in assets if isinstance(a,dict)}]
    return {"planned_runtime_seconds":round(total,2),"runtime_budget_seconds":budget,
            "runtime_over_budget":total>budget,"missing_required_assets":missing,
            "feasibility":"GAPS_FOUND" if total>budget or missing else "NUMERICALLY_WITHIN_BUDGET"}

def _cap09(e):
    platform=_nonempty(e,"target_platform")
    records=_seq(e,"verified_tool_evidence")
    preflight=assess_tool_preflight(e)
    return {"target_platform":platform,"evidence_count":len(records),
            "current_verified_count":len(preflight["matching_evidence_indexes"]),
            "platform_claims_allowed":preflight["preflight_status"]=="COMPATIBLE_FOR_HUMAN_REVIEW",
            "tool_preflight":preflight,
            "warning":"preflight is a dated registry/evidence assessment, not a live account check or generation authorisation"}

def _cap10(e):
    assets=_seq(e,"asset_manifest"); rights=_obj(e,"rights_provenance")
    findings=[]
    for i,a in enumerate(assets):
        if not isinstance(a,dict): raise SpecialistInputError("each asset must be an object")
        missing=[k for k in ("asset_id","version","location","rights_reference") if not a.get(k)]
        findings.append({"asset_index":i,"missing_fields":missing})
    return {"asset_count":len(assets),"asset_findings":findings,"rights_provenance_fields":sorted(rights),
            "recovery_status":"NOT_ASSESSED","generation_recommendation":"NONE; inspect and edit existing assets first"}

def _cap11(e):
    weights={"biblical_integrity":25,"script_narration":15,"narrative":10,"visual":10,"audio":10,
             "technical":10,"rights_provenance":10,"security_compliance":5,"audience_suitability":5}
    scores=_obj(e,"quality_dimensions"); missing=sorted(set(weights)-set(scores))
    if missing or set(scores)-set(weights): raise SpecialistInputError(f"quality_dimensions must contain exactly {sorted(weights)}")
    total=sum(_score(scores[k],k)*w for k,w in weights.items())/100
    hard_stops=_seq(e,"hard_stop_findings")
    return {"weighted_quality_score":round(total,2),"weights":weights,"hard_stop_findings":hard_stops,
            "release_recommendation":"BLOCKED_BY_HARD_STOP" if hard_stops else ("REVIEW_REQUIRED" if total<85 else "ELIGIBLE_FOR_HUMAN_ACCEPTANCE"),
            "hard_stops_cannot_be_averaged_away":True}

def _cap12(e):
    threats=_seq(e,"threats"); controls=_seq(e,"control_evidence")
    findings=[]
    controlids={c.get("control_id") for c in controls if isinstance(c,dict) and c.get("control_id")}
    for i,t in enumerate(threats):
        if not isinstance(t,dict): raise SpecialistInputError("each threat must be an object")
        findings.append({"threat_index":i,"unmapped_control":not bool(t.get("control_ids")) or any(x not in controlids for x in t.get("control_ids",[])),
                         "untrusted_input":bool(t.get("untrusted_input")),"privilege_boundary":t.get("privilege_boundary","UNASSESSED")})
    return {"threat_count":len(threats),"findings":findings,"execution_of_untrusted_instructions":False}

def _cap13(e):
    chain=_seq(e,"provenance_chain"); rights=_obj(e,"rights_basis")
    required=("asset_id","creator_or_source","rights_status","evidence_reference")
    gaps=[{"index":i,"missing":[k for k in required if not item.get(k)]} for i,item in enumerate(chain) if not isinstance(item,dict) or any(not item.get(k) for k in required)]
    return {"provenance_entries":len(chain),"provenance_gaps":gaps,"rights_basis_fields":sorted(rights),
            "clearance_status":"NOT_CLEARED" if gaps or not rights else "DOCUMENTED_FOR_HUMAN_LEGAL_REVIEW"}

def _cap14(e):
    failure=_obj(e,"failure_record"); observation=_nonempty(e,"reproduction_or_observation")
    known={"INPUT","PROCESS","TOOL","INTEGRATION","QUALITY","RIGHTS","SECURITY","UNKNOWN"}
    category=failure.get("category","UNKNOWN")
    if category not in known: raise SpecialistInputError("failure category is not recognised")
    severity=failure.get("severity","UNASSESSED")
    return {"category":category,"severity":severity,"reproduction_evidence_supplied":bool(observation),
            "root_cause":"NOT_ESTABLISHED","retry_policy":"bounded retry only after cause and safety impact are assessed"}

def _cap15(e):
    observations=_seq(e,"performance_observations"); version=_nonempty(e,"linked_production_version")
    linked=[o for o in observations if isinstance(o,dict) and o.get("production_version")==version]
    return {"linked_production_version":version,"observation_count":len(observations),
            "matching_version_observations":len(linked),"unlinked_observations":len(observations)-len(linked),
            "causal_claims_allowed":False,"learning_status":"INSUFFICIENT_LINKED_EVIDENCE" if not linked else "DESCRIPTIVE_REVIEW_ONLY"}

SPECIALISTS={"CAP-01":_cap01,"CAP-02":_cap02,"CAP-03":_cap03,"CAP-04":_cap04,"CAP-05":_cap05,
"CAP-06":_cap06,"CAP-07":_cap07,"CAP-08":_cap08,"CAP-09":_cap09,"CAP-10":_cap10,
"CAP-11":_cap11,"CAP-12":_cap12,"CAP-13":_cap13,"CAP-14":_cap14,"CAP-15":_cap15}

def assess_specialist(capability_id: str, evidence: dict) -> dict:
    if capability_id not in SPECIALISTS: raise SpecialistInputError(f"unknown capability: {capability_id}")
    if not isinstance(evidence,dict): raise SpecialistInputError("evidence must be an object")
    return SPECIALISTS[capability_id](evidence)
