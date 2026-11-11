"""Validate RhemaScript source-to-final traceability without granting execution authority."""
from __future__ import annotations

STAGES = (
    "biblical_source", "approved_script", "approved_narration", "storyboard",
    "audio_visual_plan", "clip_prompt", "asset", "edited_film"
)
GATES = (
    "creative_direction", "biblical_accuracy", "visual_development",
    "production_plan_prompt", "generation_authorisation", "final_film"
)
GATE_STAGE = {
    "creative_direction": "biblical_source",
    "biblical_accuracy": "approved_script",
    "visual_development": "storyboard",
    "production_plan_prompt": "clip_prompt",
    "generation_authorisation": "asset",
    "final_film": "edited_film",
}

class IntegrityError(ValueError):
    pass

def validate_project_chain(project):
    """Return a deterministic findings report; never performs generation or publishing."""
    errors = []
    if not isinstance(project, dict) or not project.get("project_id"):
        raise IntegrityError("project_id is required")
    stages = project.get("stages")
    approvals = project.get("approvals")
    if not isinstance(stages, dict) or not isinstance(approvals, dict):
        raise IntegrityError("stages and approvals must be objects")

    for stage in STAGES:
        record = stages.get(stage)
        if not isinstance(record, dict):
            errors.append("missing stage: " + stage)
            continue
        if not isinstance(record.get("artifact_ref"), str) or not record.get("artifact_ref").strip():
            errors.append("missing artifact reference: " + stage)
        if not record.get("source_ref"):
            errors.append("missing source reference: " + stage)
        if record.get("status") != "present":
            errors.append("stage is not evidenced as present: " + stage)
        revision = record.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            errors.append("invalid positive revision number: " + stage)

    # Each downstream artefact must explicitly identify the immediately preceding
    # approved-chain artefact it was derived from.
    for index, stage in enumerate(STAGES[1:], start=1):
        record = stages.get(stage)
        previous = stages.get(STAGES[index - 1])
        if not isinstance(record, dict) or not isinstance(previous, dict):
            continue
        upstream = record.get("upstream_refs")
        if not isinstance(upstream, list) or previous.get("artifact_ref") not in upstream:
            errors.append("missing immediate predecessor dependency: " + stage)

    # A repeated artifact reference across stages makes provenance ambiguous.
    artifact_refs = [
        stages[stage].get("artifact_ref") for stage in STAGES
        if isinstance(stages.get(stage), dict) and stages[stage].get("artifact_ref")
    ]
    if len(artifact_refs) != len(set(artifact_refs)):
        errors.append("duplicate artifact reference across source-to-final stages")

    for gate in GATES:
        record = approvals.get(gate)
        if not isinstance(record, dict):
            errors.append("missing approval gate: " + gate)
            continue
        if record.get("status") != "approved":
            errors.append("approval not granted: " + gate)
        if not record.get("approval_ref"):
            errors.append("missing approval evidence: " + gate)
        linked_stage = GATE_STAGE[gate]
        stage_record = stages.get(linked_stage, {})
        if record.get("artifact_ref") != stage_record.get("artifact_ref"):
            errors.append("approval does not reference current stage artefact: " + gate)

    history = project.get("revision_history", [])
    if not isinstance(history, list):
        errors.append("revision_history must be a list")
    else:
        observed = {stage: [] for stage in STAGES}
        for event in history:
            if not isinstance(event, dict) or event.get("stage") not in STAGES:
                errors.append("revision history contains malformed or unknown stage event")
                continue
            observed[event["stage"]].append(event)
        for stage in STAGES:
            events = observed[stage]
            stage_record = stages.get(stage)
            if not events:
                if isinstance(stage_record, dict) and stage_record.get("revision", 1) != 1:
                    errors.append("revision history missing events for revised stage: " + stage)
                continue
            expected_revision = 1
            previous_ref = None
            for event in events:
                if event.get("revision") != expected_revision:
                    errors.append("non-contiguous revision history: " + stage)
                    break
                if event.get("previous_artifact_ref") != previous_ref:
                    errors.append("broken previous-artifact link in revision history: " + stage)
                    break
                if not event.get("artifact_ref") or not event.get("source_ref") or not event.get("change_reason"):
                    errors.append("incomplete revision history event: " + stage)
                    break
                previous_ref = event["artifact_ref"]
                expected_revision += 1
            if isinstance(stage_record, dict) and (
                stage_record.get("revision") != len(events)
                or stage_record.get("artifact_ref") != previous_ref
            ):
                errors.append("revision history does not match current stage snapshot: " + stage)

    generation = project.get("generation")
    if not isinstance(generation, dict):
        errors.append("missing generation authorization record")
    else:
        if generation.get("performed") is True and generation.get("authorized") is not True:
            errors.append("critical: generation performed without authorization")
        if generation.get("authorized") is True and not generation.get("authorization_ref"):
            errors.append("generation authorization lacks evidence reference")
        if generation.get("performed") is True and generation.get("asset_ref") != stages.get("asset", {}).get("artifact_ref"):
            errors.append("generation output does not match the recorded asset")

    if project.get("published") is True:
        errors.append("publication is outside this validator's authority and requires separate authorization")

    return {
        "project_id": project["project_id"],
        "stage_count": sum(1 for s in STAGES if isinstance(stages.get(s), dict)),
        "required_stage_count": len(STAGES),
        "approval_count": sum(1 for g in GATES if isinstance(approvals.get(g), dict)),
        "required_approval_count": len(GATES),
        "valid": not errors,
        "errors": errors,
        "generation_authority": "not_granted_by_validator",
        "publishing_authority": "not_granted_by_validator",
    }
