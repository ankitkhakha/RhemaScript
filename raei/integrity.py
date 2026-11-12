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


def _nonempty_text(value):
    return isinstance(value, str) and bool(value.strip())


def validate_project_chain(project):
    """Return deterministic findings; never performs generation or publishing."""
    errors = []
    if not isinstance(project, dict) or not _nonempty_text(project.get("project_id")):
        raise IntegrityError("project_id must be a non-empty string")
    stages = project.get("stages")
    approvals = project.get("approvals")
    if not isinstance(stages, dict) or not isinstance(approvals, dict):
        raise IntegrityError("stages and approvals must be objects")
    unknown_stages = set(stages) - set(STAGES)
    unknown_gates = set(approvals) - set(GATES)
    for stage in sorted(unknown_stages, key=str):
        errors.append("unknown source-to-final stage: " + str(stage))
    for gate in sorted(unknown_gates, key=str):
        errors.append("unknown approval gate: " + str(gate))

    for stage in STAGES:
        record = stages.get(stage)
        if not isinstance(record, dict):
            errors.append("missing stage: " + stage)
            continue
        if not _nonempty_text(record.get("artifact_ref")):
            errors.append("missing artifact reference: " + stage)
        if not _nonempty_text(record.get("source_ref")):
            errors.append("missing source reference: " + stage)
        if record.get("status") != "present":
            errors.append("stage is not evidenced as present: " + stage)
        revision = record.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            errors.append("invalid positive revision number: " + stage)

    for index, stage in enumerate(STAGES[1:], start=1):
        record = stages.get(stage)
        previous = stages.get(STAGES[index - 1])
        if not isinstance(record, dict) or not isinstance(previous, dict):
            continue
        upstream = record.get("upstream_refs")
        previous_ref = previous.get("artifact_ref")
        expected_upstream = [previous_ref] if _nonempty_text(previous_ref) else None
        if not isinstance(upstream, list) or expected_upstream is None or upstream != expected_upstream:
            errors.append("immediate predecessor dependency must match exactly: " + stage)

    artifact_refs = [
        stages[stage].get("artifact_ref") for stage in STAGES
        if isinstance(stages.get(stage), dict)
        and _nonempty_text(stages[stage].get("artifact_ref"))
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
        if not _nonempty_text(record.get("approval_ref")):
            errors.append("missing approval evidence: " + gate)
        linked_stage = GATE_STAGE[gate]
        stage_record = stages.get(linked_stage)
        current_ref = stage_record.get("artifact_ref") if isinstance(stage_record, dict) else None
        if not _nonempty_text(current_ref) or record.get("artifact_ref") != current_ref:
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
                event_revision = event.get("revision")
                if (not isinstance(event_revision, int) or isinstance(event_revision, bool)
                        or event_revision != expected_revision):
                    errors.append("non-contiguous revision history: " + stage)
                    break
                if event.get("previous_artifact_ref") != previous_ref:
                    errors.append("broken previous-artifact link in revision history: " + stage)
                    break
                if not all(_nonempty_text(event.get(field))
                           for field in ("artifact_ref", "source_ref", "change_reason")):
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
        authorized = generation.get("authorized")
        performed = generation.get("performed")
        if not isinstance(authorized, bool):
            errors.append("generation authorized flag must be boolean")
        if not isinstance(performed, bool):
            errors.append("generation performed flag must be boolean")
        if performed is True and authorized is not True:
            errors.append("critical: generation performed without authorization")
        if authorized is True and not _nonempty_text(generation.get("authorization_ref")):
            errors.append("generation authorization lacks evidence reference")
        asset_record = stages.get("asset")
        asset_ref = asset_record.get("artifact_ref") if isinstance(asset_record, dict) else None
        if performed is True and (
            not _nonempty_text(generation.get("asset_ref"))
            or generation.get("asset_ref") != asset_ref
        ):
            errors.append("generation output does not match the recorded asset")

    published = project.get("published", False)
    if not isinstance(published, bool):
        errors.append("published flag must be boolean")
    elif published:
        errors.append("publication is outside this validator's authority and requires separate authorization")

    return {
        "project_id": project["project_id"],
        "stage_count": sum(1 for stage in STAGES if isinstance(stages.get(stage), dict)),
        "required_stage_count": len(STAGES),
        "approval_count": sum(1 for gate in GATES if isinstance(approvals.get(gate), dict)),
        "required_approval_count": len(GATES),
        "valid": not errors,
        "errors": errors,
        "generation_authority": "not_granted_by_validator",
        "publishing_authority": "not_granted_by_validator",
    }
