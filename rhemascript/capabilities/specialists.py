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
    beats=_seq(e,"beats")
    constraints=_obj(e,"narrative_constraints")
    narration=_seq(e,"approved_narration_segments")
    human_map=_seq(e,"human_experience_map")
    segment_ids=[]
    for i,segment in enumerate(narration):
        if not isinstance(segment,dict) or not segment.get("segment_id") or not segment.get("text"):
            raise SpecialistInputError(f"approved_narration_segments[{i}] requires segment_id and text")
        start=segment.get("start_seconds"); end=segment.get("end_seconds")
        if any(isinstance(x,bool) or not isinstance(x,(int,float)) for x in (start,end)) or start<0 or end<=start:
            raise SpecialistInputError(f"approved_narration_segments[{i}] has invalid timing")
        segment_ids.append(segment["segment_id"])
    duplicate_segments=sorted({x for x in segment_ids if segment_ids.count(x)>1})
    narration_set=set(segment_ids)
    mapped_segments=set()
    human_map_flags=[]
    for i,item in enumerate(human_map):
        if not isinstance(item,dict):
            raise SpecialistInputError("each human_experience_map entry must be an object")
        flags=[]
        if item.get("segment_id") not in narration_set: flags.append("UNKNOWN_NARRATION_SEGMENT")
        for key in ("human_tension","emotional_intention","audience_response","visual_metaphor","biblical_boundary"):
            if not item.get(key): flags.append(f"MISSING_{key.upper()}")
        if item.get("segment_id") in narration_set: mapped_segments.add(item["segment_id"])
        human_map_flags.append({"index":i,"flags":flags})
    beat_ids=[b.get("beat_id") for b in beats if isinstance(b,dict)]
    duplicate_beats=sorted({x for x in beat_ids if x and beat_ids.count(x)>1})
    beat_flags=[]
    covered_segments=set()
    for i,beat in enumerate(beats):
        if not isinstance(beat,dict): raise SpecialistInputError("each beat must be an object")
        flags=[]
        if not beat.get("purpose"): flags.append("MISSING_PURPOSE")
        refs=beat.get("narration_segment_ids",[])
        if not isinstance(refs,list) or not refs: flags.append("NO_NARRATION_MAPPING")
        else:
            unknown=[x for x in refs if x not in narration_set]
            if unknown: flags.append("UNKNOWN_NARRATION_SEGMENT")
            covered_segments.update(x for x in refs if x in narration_set)
        shot_type=beat.get("shot_type")
        if shot_type not in ("A_ROLL","B_ROLL","TRANSITION"): flags.append("INVALID_SHOT_TYPE")
        if shot_type=="B_ROLL" and not beat.get("broll_purpose"): flags.append("BROLL_PURPOSE_MISSING")
        if shot_type=="A_ROLL" and not beat.get("subject_action"): flags.append("AROLL_SUBJECT_ACTION_MISSING")
        if shot_type=="TRANSITION" and not beat.get("transition_purpose"): flags.append("TRANSITION_PURPOSE_MISSING")
        if not beat.get("visual_concept"): flags.append("VISUAL_CONCEPT_MISSING")
        beat_flags.append({"beat_index":i,"flags":flags})
    uncovered=sorted(narration_set-covered_segments)
    unmapped_human=sorted(narration_set-mapped_segments)
    duration=e.get("target_duration_seconds")
    if duration is not None and (isinstance(duration,bool) or not isinstance(duration,(int,float)) or duration<=0):
        raise SpecialistInputError("target_duration_seconds must be positive")
    structural_issues=bool(duplicate_segments or duplicate_beats or uncovered or unmapped_human or
        any(x["flags"] for x in human_map_flags) or any(x["flags"] for x in beat_flags))
    return {"approved_narration_segment_count":len(narration),"human_experience_map_count":len(human_map),
            "human_experience_map_findings":human_map_flags,"unmapped_human_experience_segments":unmapped_human,
            "beat_count":len(beats),"beat_findings":beat_flags,"duplicate_segment_ids":duplicate_segments,
            "duplicate_beat_ids":duplicate_beats,"narration_segments_without_visual_coverage":uncovered,
            "target_duration_seconds":duration,"constraints_supplied":sorted(constraints),
            "simulation_status":"STRUCTURAL_ISSUES" if structural_issues else "STRUCTURE_VALID_FOR_EDITORIAL_REVIEW",
            "interpretive_boundary":"human-experience links and visual metaphors are creative proposals, not biblical facts"}

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
    shots=_seq(e,"shot_plan")
    budget=_score(e.get("runtime_budget_seconds"),"runtime_budget_seconds")
    assets=_seq(e,"asset_inventory")
    narration=_seq(e,"approved_narration_segments")
    audio_plan=_obj(e,"audio_caption_plan")
    generation=_obj(e,"generation_constraints")
    narration_by_id={}
    for i,segment in enumerate(narration):
        if not isinstance(segment,dict) or not segment.get("segment_id") or not isinstance(segment.get("text"),str):
            raise SpecialistInputError(f"approved_narration_segments[{i}] requires segment_id and text")
        start=segment.get("start_seconds"); end=segment.get("end_seconds")
        if any(isinstance(x,bool) or not isinstance(x,(int,float)) for x in (start,end)) or start<0 or end<=start:
            raise SpecialistInputError(f"approved_narration_segments[{i}] has invalid timing")
        narration_by_id[segment["segment_id"]]=segment
    durations=[]; shot_findings=[]; required_assets=set()
    asset_ids={a.get("asset_id") for a in assets if isinstance(a,dict) and a.get("asset_id")}
    max_clip=generation.get("max_clip_seconds")
    min_clip=generation.get("min_clip_seconds",0)
    if isinstance(max_clip,bool) or not isinstance(max_clip,(int,float)) or max_clip<=0:
        raise SpecialistInputError("generation_constraints.max_clip_seconds must be positive")
    if isinstance(min_clip,bool) or not isinstance(min_clip,(int,float)) or min_clip<0 or min_clip>max_clip:
        raise SpecialistInputError("generation_constraints.min_clip_seconds must be non-negative and <= max_clip_seconds")
    target_ratio=generation.get("target_aspect_ratio")
    if target_ratio not in ("9:16","16:9","1:1"):
        raise SpecialistInputError("generation_constraints.target_aspect_ratio must be an explicit supported ratio")
    shot_ids=[]
    for i,shot in enumerate(shots):
        if not isinstance(shot,dict): raise SpecialistInputError("each shot must be an object")
        if not shot.get("shot_id"): raise SpecialistInputError(f"shot_plan[{i}] requires shot_id")
        shot_ids.append(shot["shot_id"])
        duration=shot.get("duration_seconds")
        if isinstance(duration,bool) or not isinstance(duration,(int,float)) or duration<=0:
            raise SpecialistInputError(f"shot_plan[{i}].duration_seconds must be positive")
        durations.append(float(duration))
        flags=[]
        shot_type=shot.get("shot_type")
        if shot_type not in ("A_ROLL","B_ROLL","TRANSITION"): flags.append("INVALID_SHOT_TYPE")
        if shot_type=="B_ROLL" and not shot.get("broll_purpose"): flags.append("BROLL_PURPOSE_MISSING")
        if shot_type=="A_ROLL" and not shot.get("subject_action"): flags.append("AROLL_SUBJECT_ACTION_MISSING")
        if not shot.get("purpose") or not shot.get("visual_action"): flags.append("SHOT_PURPOSE_OR_ACTION_MISSING")
        if shot.get("aspect_ratio") != target_ratio: flags.append("SHOT_ASPECT_RATIO_MISMATCH")
        if not isinstance(shot.get("generation_required"),bool): flags.append("GENERATION_REQUIRED_NOT_DECLARED")
        segment_refs=shot.get("narration_segment_ids",[])
        if not isinstance(segment_refs,list) or not segment_refs: flags.append("NO_NARRATION_MAPPING")
        else:
            unknown=[x for x in segment_refs if x not in narration_by_id]
            if unknown: flags.append("UNKNOWN_NARRATION_SEGMENT")
        asset_ref=shot.get("required_asset_id")
        if asset_ref:
            required_assets.add(asset_ref)
            if asset_ref not in asset_ids: flags.append("REQUIRED_ASSET_NOT_FOUND")
        if shot.get("generation_required") is True:
            if shot.get("asset_reviewed") is not True: flags.append("ASSET_FIRST_REVIEW_MISSING")
            if not shot.get("new_generation_justification"): flags.append("GENERATION_JUSTIFICATION_MISSING")
            if not shot.get("selected_operation") or not shot.get("selected_model"): flags.append("GENERATION_OPERATION_OR_MODEL_MISSING")
            units=shot.get("generation_unit_durations")
            if not isinstance(units,list) or not units: flags.append("GENERATION_UNITS_MISSING")
            else:
                if any(isinstance(x,bool) or not isinstance(x,(int,float)) or x<=0 or x>max_clip or (min_clip and x<min_clip) for x in units):
                    flags.append("GENERATION_UNIT_DURATION_UNSUPPORTED")
                if abs(sum(units)-duration)>0.05: flags.append("GENERATION_UNITS_DO_NOT_MATCH_SHOT_DURATION")
        shot_findings.append({"shot_id":shot["shot_id"],"flags":flags})
    duplicate_shots=sorted({x for x in shot_ids if shot_ids.count(x)>1})
    total=sum(durations)
    missing=sorted(required_assets-asset_ids)

    caption_rows=_seq(audio_plan,"caption_segments")
    caption_by_id={}
    caption_flags=[]
    for i,row in enumerate(caption_rows):
        if not isinstance(row,dict) or not row.get("segment_id"):
            raise SpecialistInputError(f"caption_segments[{i}] requires segment_id")
        if row["segment_id"] in caption_by_id: caption_flags.append("DUPLICATE_CAPTION_SEGMENT")
        caption_by_id[row["segment_id"]]=row
    if not audio_plan.get("narration_master_id"): caption_flags.append("NARRATION_MASTER_ID_MISSING")
    missing_captions=sorted(set(narration_by_id)-set(caption_by_id))
    extra_captions=sorted(set(caption_by_id)-set(narration_by_id))
    text_mismatches=[]; timing_mismatches=[]
    for sid,source in narration_by_id.items():
        caption=caption_by_id.get(sid)
        if not caption: continue
        if caption.get("text")!=source.get("text"): text_mismatches.append(sid)
        for key in ("start_seconds","end_seconds"):
            if isinstance(caption.get(key),bool) or not isinstance(caption.get(key),(int,float)) or abs(caption[key]-source.get(key,0))>0.5:
                timing_mismatches.append(sid); break
    audio_flags=[]
    audio_cues=_seq(audio_plan,"audio_cues")
    for i,cue in enumerate(audio_cues):
        if not isinstance(cue,dict): raise SpecialistInputError("each audio_cue must be an object")
        start=cue.get("start_seconds"); end=cue.get("end_seconds")
        if isinstance(start,bool) or isinstance(end,bool) or not isinstance(start,(int,float)) or not isinstance(end,(int,float)) or start<0 or end<=start:
            audio_flags.append({"index":i,"flag":"INVALID_AUDIO_CUE_TIMING"})
        elif cue.get("overlaps_narration") is True and cue.get("duck_under_narration") is not True:
            audio_flags.append({"index":i,"flag":"AUDIO_MASKING_RISK"})
    issues=bool(total>budget or missing or duplicate_shots or any(x["flags"] for x in shot_findings) or
        missing_captions or extra_captions or text_mismatches or timing_mismatches or caption_flags or audio_flags)
    return {"planned_runtime_seconds":round(total,2),"runtime_budget_seconds":budget,
            "runtime_over_budget":total>budget,"duplicate_shot_ids":duplicate_shots,
            "shot_findings":shot_findings,"missing_required_assets":missing,
            "asset_first_reviewed_shots":sum(1 for x in shots if isinstance(x,dict) and x.get("generation_required") is True and x.get("asset_reviewed") is True),
            "generation_unit_max_seconds":max_clip,"missing_caption_segments":missing_captions,
            "extra_caption_segments":extra_captions,"caption_text_mismatches":text_mismatches,
            "caption_timing_mismatches":sorted(set(timing_mismatches)),"caption_flags":caption_flags,
            "audio_findings":audio_flags,"narration_master_id":audio_plan.get("narration_master_id"),
            "feasibility":"GAPS_FOUND" if issues else "STRUCTURALLY_FEASIBLE_FOR_HUMAN_REVIEW",
            "authority_boundary":"timing/text checks do not verify audio waveform, spoken performance, or actual rendered video"}

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
