"""Authenticated RAEI finding and knowledge review transitions.

This module is a workflow boundary, not a source of identity. Callers supply
externally signed credentials; ApprovalVerifier authenticates, scopes and
atomically consumes them before the registry records a decision.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from rhemascript.core.approvals import ApprovalVerifier, ApprovalError
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry
from rhemascript.evidence.artifact_verification import (
    EvidenceVersion, is_verified_evidence_version, verify_artifact,
)


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
    evidence_root: str,
    evidence: EvidenceVersion,
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
    if not is_verified_evidence_version(evidence):
        raise RAEIGovernanceError("review requires an EvidenceVersion issued by verify_artifact")
    try:
        current = verify_artifact(
            evidence_root, evidence.relative_path,
            evidence_id=evidence.evidence_id, version=evidence.version,
        )
    except (OSError, ValueError) as exc:
        raise RAEIGovernanceError(f"review evidence could not be reverified: {exc}") from exc
    if (current.sha256 != evidence.sha256 or current.size_bytes != evidence.size_bytes):
        raise RAEIGovernanceError("review evidence bytes changed after verification")
    evidence_binding = {
        "evidence_id": current.evidence_id,
        "evidence_version": current.version,
        "sha256": current.sha256,
        "size_bytes": current.size_bytes,
    }
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
        latest = verify_artifact(
            evidence_root, evidence.relative_path,
            evidence_id=evidence.evidence_id, version=evidence.version,
        )
        if latest.sha256 != evidence.sha256 or latest.size_bytes != evidence.size_bytes:
            raise RAEIGovernanceError("review evidence bytes changed during approval")
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
    evidence_root: str,
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Record a finding disposition only after two distinct signed approvals and byte verification."""
    if disposition not in {"ACCEPTED", "REJECTED", "DUPLICATE", "DEFERRED", "WITHDRAWN"}:
        raise RAEIGovernanceError("unsupported finding disposition")
    return _record_review(
        registry, verifier, credentials,
        event_type="FINDING_DISPOSITIONED", subject_id=finding_id,
        project_id=project_id, project_version=project_version,
        subject_version=finding_version, request_id=request_id,
        decision_field="disposition", decision=disposition,
        rationale=rationale, evidence_root=evidence_root, evidence=evidence,
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
    evidence_root: str,
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Approve or reject knowledge only after two distinct signed approvals and byte verification."""
    if decision not in {"APPROVED", "REJECTED"}:
        raise RAEIGovernanceError("knowledge decision must be APPROVED or REJECTED")
    return _record_review(
        registry, verifier, credentials,
        event_type="KNOWLEDGE_REVIEWED", subject_id=knowledge_id,
        project_id=project_id, project_version=project_version,
        subject_version=knowledge_version, request_id=request_id,
        decision_field="decision", decision=decision,
        rationale=rationale, evidence_root=evidence_root, evidence=evidence,
    )


def record_finding_closure(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credentials: Sequence[object],
    *,
    finding_id: str,
    finding_version: str,
    project_id: str,
    project_version: str,
    request_id: str,
    rationale: str,
    evidence_root: str,
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Close an effective finding using two independent V3 approvals and exact lifecycle lineage."""
    if not isinstance(registry, ReadinessRunRegistry) or not isinstance(verifier, ApprovalVerifier):
        raise RAEIGovernanceError("ReadinessRunRegistry and ApprovalVerifier are required")
    if not isinstance(credentials, (tuple, list)) or len(credentials) != 2:
        raise RAEIGovernanceError("two signed closure approvals are required")
    if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 4000:
        raise RAEIGovernanceError("closure rationale must be non-empty and at most 4000 characters")
    if not is_verified_evidence_version(evidence):
        raise RAEIGovernanceError("closure requires an EvidenceVersion issued by verify_artifact")
    try:
        current = verify_artifact(
            evidence_root, evidence.relative_path,
            evidence_id=evidence.evidence_id, version=evidence.version,
        )
    except (OSError, ValueError) as exc:
        raise RAEIGovernanceError(f"closure evidence could not be reverified: {exc}") from exc
    if current.sha256 != evidence.sha256 or current.size_bytes != evidence.size_bytes:
        raise RAEIGovernanceError("closure evidence bytes changed after verification")
    events = [
        event for event in registry.list_activity_events()
        if event.get("project_id") == project_id and event.get("subject_id") == finding_id
        and event.get("payload", {}).get("finding_version") == finding_version
    ]
    by_type = {event["event_type"]: event for event in events
               if event["event_type"] in {"FINDING_PLANNED", "FINDING_IMPLEMENTED", "FINDING_EFFECTIVENESS_ASSESSED"}}
    if set(by_type) != {"FINDING_PLANNED", "FINDING_IMPLEMENTED", "FINDING_EFFECTIVENESS_ASSESSED"}:
        raise RAEIGovernanceError("closure requires plan, implementation and effectiveness events")
    plan, implementation, effectiveness = (
        by_type["FINDING_PLANNED"], by_type["FINDING_IMPLEMENTED"], by_type["FINDING_EFFECTIVENESS_ASSESSED"]
    )
    if effectiveness["payload"].get("outcome") != "EFFECTIVE":
        raise RAEIGovernanceError("only an EFFECTIVE assessment is eligible for closure")
    expected_binding = effectiveness["payload"].get("evidence_binding")
    evidence_binding = {
        "evidence_id": current.evidence_id,
        "evidence_version": current.version,
        "sha256": current.sha256,
        "size_bytes": current.size_bytes,
    }
    if evidence_binding != expected_binding:
        raise RAEIGovernanceError("closure evidence must be the exact effectiveness assessment artifact")
    actions = ("FINDING_CLOSURE_REVIEW", "FINDING_CLOSURE_CONFIRM")
    expectations = tuple({
        "action": action, "project_id": project_id,
        "project_version": project_version, "request_id": request_id,
        "artifact_binding": {
            "artifact_id": evidence_binding["evidence_id"],
            "artifact_version": evidence_binding["evidence_version"],
            "sha256": evidence_binding["sha256"],
            "size_bytes": evidence_binding["size_bytes"],
        },
    } for action in actions)
    try:
        approvals = verifier.verify_many_and_consume(
            tuple(credentials), expectations, require_distinct_actors=True,
        )
        latest = verify_artifact(
            evidence_root, evidence.relative_path,
            evidence_id=evidence.evidence_id, version=evidence.version,
        )
        if latest.sha256 != evidence.sha256 or latest.size_bytes != evidence.size_bytes:
            raise RAEIGovernanceError("closure evidence changed during approval")
        payload = {
            "finding_id": finding_id,
            "finding_version": finding_version,
            "closure_decision": "CLOSED",
            "rationale": rationale,
            "evidence_binding": evidence_binding,
            "lifecycle_lineage": {
                "plan_event_id": plan["event_id"],
                "implementation_event_id": implementation["event_id"],
                "effectiveness_event_id": effectiveness["event_id"],
            },
        }
        event_id = f"FINDING_CLOSED:{finding_id}@{finding_version}:{request_id}"
        recorded = registry.append_governed_activity_event(
            event_id, "FINDING_CLOSED", payload,
            project_id=project_id, project_version=project_version,
            subject_id=finding_id, request_id=request_id,
            approvals=approvals, expected_actions=actions,
        )
    except (ApprovalError, ValueError, TypeError) as exc:
        raise RAEIGovernanceError(f"governed finding closure rejected: {exc}") from exc
    return {
        "recorded": recorded, "event_id": event_id,
        "finding_id": finding_id, "finding_version": finding_version,
        "decision": "CLOSED", "authenticated_reviewers": 2,
        "approval_ids": [item.approval_id for item in approvals],
    }


def list_governed_reviews(
    registry: ReadinessRunRegistry, *, event_type: str | None = None,
    project_id: str | None = None, subject_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return decisions only after validating the registry chain and review envelope."""
    if not isinstance(registry, ReadinessRunRegistry) or not registry.verify():
        raise RAEIGovernanceError("activity history integrity verification failed")
    allowed = {"FINDING_DISPOSITIONED", "FINDING_CLOSED", "KNOWLEDGE_REVIEWED"}
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
        if event["event_type"] == "FINDING_CLOSED":
            subjects = auth.get("subject_ids", [])
            sessions = auth.get("identity_session_ids", [])
            providers = auth.get("identity_provider_ids", [])
            policies = auth.get("identity_policy_versions", [])
            if (len(subjects) != 2 or len(set(subjects)) != 2
                    or len(sessions) != 2 or len(set(sessions)) != 2
                    or len(providers) != 2 or len(set(providers)) != 1
                    or len(policies) != 2 or len(set(policies)) != 1
                    or auth.get("actions") != ["FINDING_CLOSURE_REVIEW", "FINDING_CLOSURE_CONFIRM"]):
                raise RAEIGovernanceError("finding closure must retain two distinct authenticated reviewers in one identity domain")
        results.append({**event, **payload})
    return results
