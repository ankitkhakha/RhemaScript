"""Authenticated RAEI finding and knowledge review transitions.

This module is a workflow boundary, not a source of identity. Callers supply
externally signed credentials; ApprovalVerifier authenticates, scopes and
atomically consumes them before the registry records a decision.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from rhemascript.core.approvals import ApprovalVerifier, ApprovalError
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry


class RAEIGovernanceError(ValueError):
    """A governed RAEI review could not be authenticated or recorded."""


def _record_review(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credentials: Sequence[object],
    *,
    event_type: str,
    subject_id: str,
    project_id: str,
    project_version: str,
    subject_version: str,
    request_id: str,
    decision_field: str,
    decision: str,
    rationale: str,
    evidence_binding: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(registry, ReadinessRunRegistry):
        raise RAEIGovernanceError("ReadinessRunRegistry is required")
    if not isinstance(verifier, ApprovalVerifier):
        raise RAEIGovernanceError("ApprovalVerifier is required")
    if not isinstance(credentials, (tuple, list)) or len(credentials) != 2:
        raise RAEIGovernanceError("two signed approval credentials are required")
    for name, value in (
        ("subject_id", subject_id), ("project_id", project_id),
        ("project_version", project_version), ("subject_version", subject_version),
        ("request_id", request_id), ("decision", decision), ("rationale", rationale),
    ):
        if not isinstance(value, str) or not value.strip():
            raise RAEIGovernanceError(f"{name} must be non-empty text")
    if not isinstance(evidence_binding, Mapping):
        raise RAEIGovernanceError("exact evidence binding is required")
    actions = (
        ("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM")
        if event_type == "FINDING_DISPOSITIONED"
        else ("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM")
    )
    expectations = tuple({
        "action": action,
        "project_id": project_id,
        "project_version": project_version,
        "request_id": request_id,
    } for action in actions)
    try:
        approvals = verifier.verify_many_and_consume(
            tuple(credentials), expectations, require_distinct_actors=True,
        )
        if event_type == "FINDING_DISPOSITIONED":
            payload = {
                "finding_id": subject_id,
                "finding_version": subject_version,
                decision_field: decision,
                "rationale": rationale,
                "evidence_binding": dict(evidence_binding),
            }
        else:
            payload = {
                "knowledge_id": subject_id,
                "knowledge_version": subject_version,
                decision_field: decision,
                "rationale": rationale,
                "evidence_binding": dict(evidence_binding),
            }
        event_id = f"{event_type}:{subject_id}@{subject_version}:{request_id}"
        recorded = registry.append_governed_activity_event(
            event_id, event_type, payload,
            project_id=project_id, project_version=project_version,
            subject_id=subject_id, request_id=request_id,
            approvals=approvals, expected_actions=actions,
        )
    except (ApprovalError, ValueError, TypeError) as exc:
        raise RAEIGovernanceError(f"governed review rejected: {exc}") from exc
    return {
        "recorded": recorded,
        "event_id": event_id,
        "subject_id": subject_id,
        "subject_version": subject_version,
        "decision": decision,
        "authenticated_reviewers": 2,
        "approval_ids": [item.approval_id for item in approvals],
    }


def record_finding_disposition(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credentials: Sequence[object],
    *,
    finding_id: str,
    finding_version: str,
    project_id: str,
    project_version: str,
    request_id: str,
    disposition: str,
    rationale: str,
    evidence_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Record a finding disposition only after two distinct signed approvals."""
    if disposition not in {"ACCEPTED", "REJECTED", "DUPLICATE", "DEFERRED", "WITHDRAWN"}:
        raise RAEIGovernanceError("unsupported finding disposition")
    return _record_review(
        registry, verifier, credentials,
        event_type="FINDING_DISPOSITIONED", subject_id=finding_id,
        project_id=project_id, project_version=project_version,
        subject_version=finding_version, request_id=request_id,
        decision_field="disposition", decision=disposition,
        rationale=rationale, evidence_binding=evidence_binding,
    )


def record_knowledge_review(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credentials: Sequence[object],
    *,
    knowledge_id: str,
    knowledge_version: str,
    project_id: str,
    project_version: str,
    request_id: str,
    decision: str,
    rationale: str,
    evidence_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Approve or reject knowledge only after two distinct signed approvals."""
    if decision not in {"APPROVED", "REJECTED"}:
        raise RAEIGovernanceError("knowledge decision must be APPROVED or REJECTED")
    return _record_review(
        registry, verifier, credentials,
        event_type="KNOWLEDGE_REVIEWED", subject_id=knowledge_id,
        project_id=project_id, project_version=project_version,
        subject_version=knowledge_version, request_id=request_id,
        decision_field="decision", decision=decision,
        rationale=rationale, evidence_binding=evidence_binding,
    )


def list_governed_reviews(
    registry: ReadinessRunRegistry, *, event_type: str | None = None,
    project_id: str | None = None, subject_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return decisions only after validating the registry chain and review envelope."""
    if not isinstance(registry, ReadinessRunRegistry) or not registry.verify():
        raise RAEIGovernanceError("activity history integrity verification failed")
    allowed = {"FINDING_DISPOSITIONED", "KNOWLEDGE_REVIEWED"}
    if event_type is not None and event_type not in allowed:
        raise RAEIGovernanceError("unsupported governed review filter")
    results = []
    for event in registry.list_activity_events():
        if event["event_type"] not in allowed:
            continue
        if event_type is not None and event["event_type"] != event_type:
            continue
        if project_id is not None and event.get("project_id") != project_id:
            continue
        if subject_id is not None and event.get("subject_id") != subject_id:
            continue
        payload = event["payload"]
        auth = payload.get("authorization")
        if (not isinstance(auth, dict)
                or len(auth.get("actor_ids", [])) != 2
                or len(set(auth.get("actor_ids", []))) != 2
                or len(auth.get("approval_ids", [])) != 2
                or auth.get("project_id") != event.get("project_id")):
            raise RAEIGovernanceError("governed event authorization envelope is invalid")
        results.append({**event, **payload})
    return results
