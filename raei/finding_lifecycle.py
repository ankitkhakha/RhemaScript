"""V3-authenticated RAEI finding research and reproduction transitions.

Research and reproduction are separate, version-bound events. Each event
requires a signed V3 approval bound to the exact report artifact. Reproduction
must be performed by a different human subject from the researcher and, when
known, the authenticated submitter.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re
from typing import Any

from rhemascript.core.approvals import ApprovalVerifier, ApprovalError
from rhemascript.evidence.artifact_verification import (
    EvidenceVersion, is_verified_evidence_version, verify_artifact,
)
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry


class RAEIFindingLifecycleError(ValueError):
    """A finding research or reproduction transition failed validation."""


def _required_text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RAEIFindingLifecycleError(f"{field} must be non-empty trimmed text")
    return value


def _string_list(payload: dict[str, Any], field: str, *, required: bool = False) -> list[str]:
    value = payload.get(field)
    if not isinstance(value, list) or (required and not value):
        raise RAEIFindingLifecycleError(f"{field} must be a {'non-empty ' if required else ''}list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise RAEIFindingLifecycleError(f"{field} must contain only non-empty strings")
    return value


def _load_exact_report(
    registry: ReadinessRunRegistry,
    evidence_root: str,
    artifact_bytes: bytes,
    evidence: EvidenceVersion,
    *,
    schema: str,
    finding_id: str,
    finding_version: str,
) -> dict[str, Any]:
    if not isinstance(registry, ReadinessRunRegistry) or not registry.verify_artifacts(evidence_root):
        raise RAEIFindingLifecycleError("existing finding registry or retained evidence failed integrity verification")
    if not is_verified_evidence_version(evidence):
        raise RAEIFindingLifecycleError("lifecycle report requires an EvidenceVersion from verify_artifact")
    if not isinstance(artifact_bytes, bytes):
        raise RAEIFindingLifecycleError("lifecycle report must be supplied as exact bytes")
    try:
        current = verify_artifact(
            evidence_root, evidence.relative_path,
            evidence_id=evidence.evidence_id, version=evidence.version,
        )
    except (OSError, ValueError) as exc:
        raise RAEIFindingLifecycleError(f"lifecycle report could not be reverified: {exc}") from exc
    if (current.sha256 != evidence.sha256 or current.size_bytes != evidence.size_bytes
            or hashlib.sha256(artifact_bytes).hexdigest() != evidence.sha256
            or len(artifact_bytes) != evidence.size_bytes):
        raise RAEIFindingLifecycleError("lifecycle report bytes do not match the verified evidence version")
    try:
        payload = json.loads(artifact_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RAEIFindingLifecycleError("lifecycle report must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema") != schema:
        raise RAEIFindingLifecycleError("unsupported finding lifecycle report schema")
    if payload.get("finding_id") != finding_id or payload.get("finding_version") != finding_version:
        raise RAEIFindingLifecycleError("lifecycle report must identify the exact finding version")
    if payload.get("evidence_id") != evidence.evidence_id or payload.get("evidence_version") != evidence.version:
        raise RAEIFindingLifecycleError("lifecycle report must identify its exact verified evidence version")
    created_at = _required_text(payload, "created_at_utc")
    try:
        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RAEIFindingLifecycleError("created_at_utc must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RAEIFindingLifecycleError("created_at_utc must include a timezone")
    return payload


def _record_transition(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credential: object,
    *,
    event_type: str,
    action: str,
    finding_id: str,
    finding_version: str,
    project_id: str,
    project_version: str,
    request_id: str,
    evidence_root: str,
    artifact_bytes: bytes,
    evidence: EvidenceVersion,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(verifier, ApprovalVerifier):
        raise RAEIFindingLifecycleError("ApprovalVerifier is required")
    for name, value in (
        ("finding_id", finding_id), ("finding_version", finding_version),
        ("project_id", project_id), ("project_version", project_version),
        ("request_id", request_id),
    ):
        if not isinstance(value, str) or not value.strip():
            raise RAEIFindingLifecycleError(f"{name} must be non-empty text")
    binding = {
        "evidence_id": evidence.evidence_id,
        "evidence_version": evidence.version,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
    }
    event_payload = dict(payload)
    event_payload["evidence_binding"] = binding
    event_payload["evidence_refs"] = [{
        "evidence_id": evidence.evidence_id,
        "relative_path": evidence.relative_path,
        "version": evidence.version,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
        "description": "Exact research/reproduction report",
    }]
    try:
        approval = verifier.verify_many_and_consume(
            (credential,),
            ({
                "action": action,
                "project_id": project_id,
                "project_version": project_version,
                "request_id": request_id,
                "artifact_binding": {
                    "artifact_id": evidence.evidence_id,
                    "artifact_version": evidence.version,
                    "sha256": evidence.sha256,
                    "size_bytes": evidence.size_bytes,
                },
            },),
            require_distinct_actors=False,
        )[0]
        latest = verify_artifact(
            evidence_root, evidence.relative_path,
            evidence_id=evidence.evidence_id, version=evidence.version,
        )
        if latest.sha256 != evidence.sha256 or latest.size_bytes != evidence.size_bytes:
            raise RAEIFindingLifecycleError("lifecycle evidence changed during approval")
        event_id = f"{event_type}:{finding_id}@{finding_version}:{request_id}"
        recorded = registry.append_authenticated_finding_lifecycle_event(
            event_id, event_type, event_payload,
            project_id=project_id, project_version=project_version,
            request_id=request_id, approval=approval,
        )
    except (ApprovalError, OSError, ValueError, TypeError) as exc:
        if isinstance(exc, RAEIFindingLifecycleError):
            raise
        raise RAEIFindingLifecycleError(f"authenticated finding lifecycle transition rejected: {exc}") from exc
    return {
        "recorded": recorded,
        "event_id": event_id,
        "finding_id": finding_id,
        "finding_version": finding_version,
        "status": (
            "RESEARCHED" if event_type == "FINDING_RESEARCHED"
            else payload["outcome"] if event_type == "FINDING_REPRODUCED"
            else "PLANNED"
        ),
        "approval_id": approval.approval_id,
        "authenticated_subject_id": approval.subject_id,
        "evidence_binding": binding,
    }


def record_finding_research(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credential: object,
    *,
    finding_id: str,
    finding_version: str,
    project_id: str,
    project_version: str,
    request_id: str,
    evidence_root: str,
    artifact_bytes: bytes,
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Record an exact research report after a consumed V3 FINDING_RESEARCH approval."""
    payload = _load_exact_report(
        registry, evidence_root, artifact_bytes, evidence,
        schema="raei-finding-research-v1",
        finding_id=finding_id, finding_version=finding_version,
    )
    required = {
        "schema", "finding_id", "finding_version", "research_question", "methodology",
        "findings", "knowledge_gaps", "limitations", "evidence_id", "evidence_version",
        "created_at_utc",
    }
    if set(payload) != required:
        raise RAEIFindingLifecycleError("research report has an invalid field set")
    for field in ("research_question", "methodology"):
        _required_text(payload, field)
    _string_list(payload, "findings", required=True)
    _string_list(payload, "knowledge_gaps")
    _string_list(payload, "limitations")
    return _record_transition(
        registry, verifier, credential,
        event_type="FINDING_RESEARCHED", action="FINDING_RESEARCH",
        finding_id=finding_id, finding_version=finding_version,
        project_id=project_id, project_version=project_version,
        request_id=request_id, evidence_root=evidence_root,
        artifact_bytes=artifact_bytes, evidence=evidence, payload=payload,
    )


def record_finding_reproduction(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credential: object,
    *,
    finding_id: str,
    finding_version: str,
    project_id: str,
    project_version: str,
    request_id: str,
    evidence_root: str,
    artifact_bytes: bytes,
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Record an independently authenticated reproduction outcome after prior research."""
    payload = _load_exact_report(
        registry, evidence_root, artifact_bytes, evidence,
        schema="raei-finding-reproduction-v1",
        finding_id=finding_id, finding_version=finding_version,
    )
    required = {
        "schema", "finding_id", "finding_version", "outcome", "environment", "steps",
        "expected_behavior", "observed_behavior", "evidence_id", "evidence_version",
        "created_at_utc",
    }
    if set(payload) != required:
        raise RAEIFindingLifecycleError("reproduction report has an invalid field set")
    if payload.get("outcome") not in {"REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE"}:
        raise RAEIFindingLifecycleError("reproduction outcome is unsupported")
    for field in ("environment", "expected_behavior", "observed_behavior"):
        _required_text(payload, field)
    _string_list(payload, "steps", required=True)
    return _record_transition(
        registry, verifier, credential,
        event_type="FINDING_REPRODUCED", action="FINDING_REPRODUCE",
        finding_id=finding_id, finding_version=finding_version,
        project_id=project_id, project_version=project_version,
        request_id=request_id, evidence_root=evidence_root,
        artifact_bytes=artifact_bytes, evidence=evidence, payload=payload,
    )


def record_finding_implementation(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credential: object,
    *,
    finding_id: str,
    finding_version: str,
    project_id: str,
    project_version: str,
    request_id: str,
    evidence_root: str,
    artifact_bytes: bytes,
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Record actual implementation against the exact previously approved plan."""
    payload = _load_exact_report(
        registry, evidence_root, artifact_bytes, evidence,
        schema="raei-finding-implementation-v1",
        finding_id=finding_id, finding_version=finding_version,
    )
    required = {
        "schema", "finding_id", "finding_version", "plan_event_id", "plan_evidence_binding",
        "implementation_summary", "changes", "test_results", "deviations", "rollback_reference",
        "evidence_id", "evidence_version", "created_at_utc",
    }
    if set(payload) != required:
        raise RAEIFindingLifecycleError("implementation report has an invalid field set")
    for field in ("plan_event_id", "implementation_summary", "rollback_reference"):
        _required_text(payload, field)
    for field in ("changes", "test_results"):
        _string_list(payload, field, required=True)
    _string_list(payload, "deviations")
    if not isinstance(payload.get("plan_evidence_binding"), dict):
        raise RAEIFindingLifecycleError("implementation report requires exact plan evidence binding")
    if not isinstance(verifier, ApprovalVerifier):
        raise RAEIFindingLifecycleError("ApprovalVerifier is required")
    binding = {
        "evidence_id": evidence.evidence_id,
        "evidence_version": evidence.version,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
    }
    enriched = dict(payload)
    enriched["evidence_binding"] = binding
    enriched["evidence_refs"] = [{
        "evidence_id": evidence.evidence_id,
        "relative_path": evidence.relative_path,
        "version": evidence.version,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
        "description": "Exact implementation report",
    }]
    try:
        approval = verifier.verify_many_and_consume(
            (credential,),
            ({
                "action": "FINDING_IMPLEMENT",
                "project_id": project_id,
                "project_version": project_version,
                "request_id": request_id,
                "artifact_binding": {
                    "artifact_id": evidence.evidence_id,
                    "artifact_version": evidence.version,
                    "sha256": evidence.sha256,
                    "size_bytes": evidence.size_bytes,
                },
            },),
            require_distinct_actors=False,
        )[0]
        latest = verify_artifact(
            evidence_root, evidence.relative_path,
            evidence_id=evidence.evidence_id, version=evidence.version,
        )
        if latest.sha256 != evidence.sha256 or latest.size_bytes != evidence.size_bytes:
            raise RAEIFindingLifecycleError("implementation evidence changed during approval")
        event_id = f"FINDING_IMPLEMENTED:{finding_id}@{finding_version}:{request_id}"
        recorded = registry.append_authenticated_finding_implementation_event(
            event_id, enriched,
            project_id=project_id, project_version=project_version,
            request_id=request_id, approval=approval,
        )
    except (ApprovalError, OSError, ValueError, TypeError) as exc:
        if isinstance(exc, RAEIFindingLifecycleError):
            raise
        raise RAEIFindingLifecycleError(f"authenticated implementation transition rejected: {exc}") from exc
    return {
        "recorded": recorded,
        "event_id": event_id,
        "finding_id": finding_id,
        "finding_version": finding_version,
        "status": "IMPLEMENTED",
        "approval_id": approval.approval_id,
        "authenticated_subject_id": approval.subject_id,
        "evidence_binding": binding,
        "plan_event_id": payload["plan_event_id"],
    }



def record_finding_plan(
    registry: ReadinessRunRegistry,
    verifier: ApprovalVerifier,
    credential: object,
    *,
    finding_id: str,
    finding_version: str,
    project_id: str,
    project_version: str,
    request_id: str,
    evidence_root: str,
    artifact_bytes: bytes,
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Record an approved execution plan after accepted disposition and reproduced evidence."""
    payload = _load_exact_report(
        registry, evidence_root, artifact_bytes, evidence,
        schema="raei-finding-plan-v1",
        finding_id=finding_id, finding_version=finding_version,
    )
    required = {
        "schema", "finding_id", "finding_version", "plan_objective", "scope",
        "tasks", "milestones", "acceptance_criteria", "dependencies", "risks",
        "rollback_plan", "evidence_id", "evidence_version", "created_at_utc",
    }
    if set(payload) != required:
        raise RAEIFindingLifecycleError("plan report has an invalid field set")
    for field in ("plan_objective", "scope", "rollback_plan"):
        _required_text(payload, field)
    for field in ("tasks", "milestones", "acceptance_criteria"):
        _string_list(payload, field, required=True)
    for field in ("dependencies", "risks"):
        _string_list(payload, field)
    return _record_transition(
        registry, verifier, credential,
        event_type="FINDING_PLANNED", action="FINDING_PLAN",
        finding_id=finding_id, finding_version=finding_version,
        project_id=project_id, project_version=project_version,
        request_id=request_id, evidence_root=evidence_root,
        artifact_bytes=artifact_bytes, evidence=evidence, payload=payload,
    )
