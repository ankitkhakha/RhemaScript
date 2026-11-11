"""Create and revise traceable RhemaScript project records.

This module edits metadata only. It never approves gates, authorizes generation,
creates media, or publishes.
"""
from __future__ import annotations

from copy import deepcopy

from raei.integrity import GATES, GATE_STAGE, STAGES, IntegrityError


def create_project_record(project_id):
    """Return an empty project record with every gate explicitly pending."""
    if not isinstance(project_id, str) or not project_id.strip():
        raise IntegrityError("project_id must be a non-empty string")
    return {
        "project_id": project_id,
        "stages": {},
        "approvals": {
            gate: {"status": "pending", "approval_ref": None, "artifact_ref": None}
            for gate in GATES
        },
        "generation": {
            "authorized": False,
            "performed": False,
            "authorization_ref": None,
            "asset_ref": None,
        },
        "published": False,
        "revision_history": [],
    }


def revise_stage(project, stage, artifact_ref, source_ref, change_reason, upstream_refs=None):
    """Return a revised copy; invalidate affected approvals and append an audit event."""
    if not isinstance(project, dict) or not project.get("project_id"):
        raise IntegrityError("project with project_id is required")
    if stage not in STAGES:
        raise IntegrityError("unknown source-to-final stage: " + str(stage))
    for field, value in (
        ("artifact_ref", artifact_ref),
        ("source_ref", source_ref),
        ("change_reason", change_reason),
    ):
        if not isinstance(value, str) or not value.strip():
            raise IntegrityError(field + " must be a non-empty string")

    result = deepcopy(project)
    stages = result.setdefault("stages", {})
    index = STAGES.index(stage)
    expected_upstream = []
    if index:
        predecessor = stages.get(STAGES[index - 1])
        if not isinstance(predecessor, dict) or not predecessor.get("artifact_ref"):
            raise IntegrityError("preceding stage must exist before revising " + stage)
        expected_upstream = [predecessor["artifact_ref"]]

    supplied_upstream = expected_upstream if upstream_refs is None else upstream_refs
    if not isinstance(supplied_upstream, list) or supplied_upstream != expected_upstream:
        raise IntegrityError("upstream_refs must exactly match the immediate predecessor")

    prior = stages.get(stage, {})
    revision = prior.get("revision", 0) + 1
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise IntegrityError("existing stage revision is invalid")
    stages[stage] = {
        "status": "present",
        "artifact_ref": artifact_ref,
        "source_ref": source_ref,
        "revision": revision,
        "upstream_refs": list(supplied_upstream),
    }

    approvals = result.setdefault("approvals", {})
    affected_index = index
    for gate in GATES:
        gate_stage_index = STAGES.index(GATE_STAGE[gate])
        if gate_stage_index >= affected_index:
            approvals[gate] = {
                "status": "pending",
                "approval_ref": None,
                "artifact_ref": None,
            }

    result.setdefault("revision_history", []).append({
        "stage": stage,
        "revision": revision,
        "previous_artifact_ref": prior.get("artifact_ref"),
        "artifact_ref": artifact_ref,
        "source_ref": source_ref,
        "change_reason": change_reason,
        "invalidated_gates": [
            gate for gate in GATES
            if STAGES.index(GATE_STAGE[gate]) >= affected_index
        ],
    })
    return result
