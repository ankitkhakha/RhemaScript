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
    if (not isinstance(project, dict) or not isinstance(project.get("project_id"), str)
        or not project["project_id"].strip()):
        raise IntegrityError("project with non-empty string project_id is required")
    if not isinstance(stage, str) or stage not in STAGES:
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
    if not isinstance(stages, dict):
        raise IntegrityError("stages must be an object")
    history = result.setdefault("revision_history", [])
    if not isinstance(history, list):
        raise IntegrityError("revision_history must be a list")
    approvals_existing = result.setdefault("approvals", {})
    if not isinstance(approvals_existing, dict):
        raise IntegrityError("approvals must be an object")
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
    if not isinstance(prior, dict):
        raise IntegrityError("existing stage record must be an object")
    previous_revision = prior.get("revision", 0)
    if not isinstance(previous_revision, int) or isinstance(previous_revision, bool) or previous_revision < 0:
        raise IntegrityError("existing stage revision is invalid")
    revision = previous_revision + 1
    stages[stage] = {
        "status": "present",
        "artifact_ref": artifact_ref,
        "source_ref": source_ref,
        "revision": revision,
        "upstream_refs": list(supplied_upstream),
    }

    approvals = approvals_existing
    affected_index = index
    for gate in GATES:
        gate_stage_index = STAGES.index(GATE_STAGE[gate])
        if gate_stage_index >= affected_index:
            approvals[gate] = {
                "status": "pending",
                "approval_ref": None,
                "artifact_ref": None,
            }

    history.append({
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


def compare_project_records(before, after):
    """Return a deterministic change and approval-impact report for two snapshots."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise IntegrityError("both project snapshots must be objects")
    if (not isinstance(before.get("project_id"), str) or not before["project_id"].strip()
        or before.get("project_id") != after.get("project_id"):
        raise IntegrityError("snapshots must share the same non-empty project_id")
    before_stages = before.get("stages", {})
    after_stages = after.get("stages", {})
    if not isinstance(before_stages, dict) or not isinstance(after_stages, dict):
        raise IntegrityError("stage collections must be objects")
    changes = []
    affected_gates = set()
    for stage in STAGES:
        old = before_stages.get(stage, {})
        new = after_stages.get(stage, {})
        if not isinstance(old, dict) or not isinstance(new, dict):
            raise IntegrityError("stage records must be objects")
        old_ref, new_ref = old.get("artifact_ref"), new.get("artifact_ref")
        old_revision, new_revision = old.get("revision"), new.get("revision")
        if old_ref != new_ref or old_revision != new_revision:
            changes.append({
                "stage": stage,
                "before_artifact_ref": old_ref,
                "after_artifact_ref": new_ref,
                "before_revision": old_revision,
                "after_revision": new_revision,
            })
            stage_index = STAGES.index(stage)
            affected_gates.update(
                gate for gate in GATES
                if STAGES.index(GATE_STAGE[gate]) >= stage_index
            )
    approvals_after = after.get("approvals", {})
    if not isinstance(approvals_after, dict):
        raise IntegrityError("approval collection must be an object")
    invalidated = [
        gate for gate in GATES
        if gate in affected_gates
        and (
            not isinstance(approvals_after.get(gate), dict)
            or approvals_after[gate].get("status") != "approved"
            or not approvals_after[gate].get("approval_ref")
        )
    ]
    return {
        "project_id": before["project_id"],
        "changed_stages": changes,
        "affected_gates": [gate for gate in GATES if gate in affected_gates],
        "gates_without_current_approval_evidence": invalidated,
        "requires_review": bool(changes or invalidated),
        "generation_authority": "not_granted_by_comparison",
        "publishing_authority": "not_granted_by_comparison",
    }
