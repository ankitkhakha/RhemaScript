"""Field observation intake over the existing RAEI activity-event registry.

A captured finding is an immutable, evidence-linked submission. Intake does not
assert that the observation is true, reproduce it, approve a solution or grant
implementation authority.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from rhemascript.core.approvals import ApprovalVerifier, ApprovalError
from rhemascript.evidence.artifact_verification import (
    EvidenceVersion, is_verified_evidence_version, verify_artifact,
)
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry

SCHEMA = "raei-field-finding-v1"
_FINDING_ID = re.compile(r"^RS-FND-[A-Z0-9][A-Z0-9._:-]{1,100}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
_SUPERSEDES = re.compile(r"^RS-FND-[A-Z0-9][A-Z0-9._:-]{1,100}@[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
_REQUIRED_FIELDS = {
    "schema", "finding_id", "version", "project_id", "title", "raw_observation",
    "affected_workflow", "expected_behavior", "observed_behavior", "impact",
    "reproduction_steps", "supporting_evidence", "evidence_id", "evidence_version",
    "created_at_utc",
}
_OPTIONAL_FIELDS = {"tags", "related_work_ids", "supersedes", "submitted_by_label", "redaction_note"}


class RAEIFindingError(ValueError):
    """A field-finding artifact failed intake validation."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RAEIFindingError("finding artifact must contain canonical JSON values") from exc


def _text(payload: dict[str, Any], field: str, *, preserve: bool = False) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RAEIFindingError(f"{field} must be a non-empty string")
    if not preserve and value != value.strip():
        raise RAEIFindingError(f"{field} must not have surrounding whitespace")
    return value if preserve else value.strip()


def _string_list(value: Any, field: str, *, required: bool = False) -> list[str]:
    if not isinstance(value, list) or (required and not value):
        raise RAEIFindingError(f"{field} must be a {'non-empty ' if required else ''}list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise RAEIFindingError(f"{field} must contain only non-empty strings")
    return value


def _validate_timestamp(value: Any) -> None:
    if not isinstance(value, str):
        raise RAEIFindingError("created_at_utc must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RAEIFindingError("created_at_utc must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RAEIFindingError("created_at_utc must include a timezone")


def capture_finding(
    registry: ReadinessRunRegistry,
    evidence_root: str | Path,
    artifact_bytes: bytes,
    evidence: EvidenceVersion,
    *,
    verifier: ApprovalVerifier | None = None,
    submitter_credential: object | None = None,
    project_version: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Capture an exact observation; optionally bind the submitter to a V3 signed identity approval."""
    if not isinstance(registry, ReadinessRunRegistry):
        raise RAEIFindingError("a ReadinessRunRegistry is required")
    if not is_verified_evidence_version(evidence):
        raise RAEIFindingError("finding intake requires evidence returned by verify_artifact")
    if not isinstance(artifact_bytes, bytes):
        raise RAEIFindingError("finding artifact must be supplied as exact bytes")
    if not registry.verify_artifacts(evidence_root):
        raise RAEIFindingError("existing RAEI registry or retained evidence failed integrity verification")
    current_evidence = verify_artifact(
        evidence_root, evidence.relative_path,
        evidence_id=evidence.evidence_id, version=evidence.version,
    )
    if (current_evidence.sha256 != evidence.sha256
            or current_evidence.size_bytes != evidence.size_bytes
            or hashlib.sha256(artifact_bytes).hexdigest() != evidence.sha256
            or len(artifact_bytes) != evidence.size_bytes):
        raise RAEIFindingError("finding artifact bytes do not match the current verified evidence version")
    try:
        payload = json.loads(artifact_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RAEIFindingError("finding artifact must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise RAEIFindingError("finding artifact root must be an object")
    if not _REQUIRED_FIELDS.issubset(payload):
        raise RAEIFindingError("finding artifact is missing required fields")
    if set(payload) - _REQUIRED_FIELDS - _OPTIONAL_FIELDS:
        raise RAEIFindingError("finding artifact contains unsupported fields")
    if payload.get("schema") != SCHEMA:
        raise RAEIFindingError("unsupported finding schema")
    finding_id = _text(payload, "finding_id")
    if not _FINDING_ID.fullmatch(finding_id):
        raise RAEIFindingError("finding_id must use the RS-FND-... identifier form")
    version = _text(payload, "version")
    if not _VERSION.fullmatch(version):
        raise RAEIFindingError("version must use numeric major.minor[.patch] format")
    project_id = _text(payload, "project_id")
    title = _text(payload, "title")
    raw_observation = _text(payload, "raw_observation", preserve=True)
    workflow = _text(payload, "affected_workflow")
    expected = _text(payload, "expected_behavior", preserve=True)
    observed = _text(payload, "observed_behavior", preserve=True)
    impact = _text(payload, "impact", preserve=True)
    if payload.get("evidence_id") != evidence.evidence_id or payload.get("evidence_version") != evidence.version:
        raise RAEIFindingError("finding artifact does not identify its exact verified evidence version")
    _validate_timestamp(payload.get("created_at_utc"))
    reproduction_steps = _string_list(payload.get("reproduction_steps"), "reproduction_steps")
    supporting = payload.get("supporting_evidence")
    if not isinstance(supporting, list):
        raise RAEIFindingError("supporting_evidence must be a list")
    tags = _string_list(payload.get("tags", []), "tags")
    related_work_ids = _string_list(payload.get("related_work_ids", []), "related_work_ids")
    supersedes = _string_list(payload.get("supersedes", []), "supersedes")
    if any(not _SUPERSEDES.fullmatch(item) for item in supersedes):
        raise RAEIFindingError("supersedes entries must use RS-FND-ID@version format")
    submitted_by = payload.get("submitted_by_label")
    if submitted_by is not None and (not isinstance(submitted_by, str) or not submitted_by.strip()):
        raise RAEIFindingError("submitted_by_label must be null or non-empty text")
    redaction_note = payload.get("redaction_note")
    if redaction_note is not None and (not isinstance(redaction_note, str) or not redaction_note.strip()):
        raise RAEIFindingError("redaction_note must be null or non-empty text")

    primary_ref = {
        "evidence_id": evidence.evidence_id,
        "relative_path": evidence.relative_path,
        "version": evidence.version,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
        "description": "Original field-finding submission",
    }
    supporting_refs = []
    seen_evidence = {evidence.evidence_id}
    root = Path(evidence_root).expanduser()
    for index, item in enumerate(supporting):
        if not isinstance(item, dict) or set(item) != {
            "evidence_id", "version", "relative_path", "description"
        }:
            raise RAEIFindingError(
                f"supporting_evidence[{index}] requires evidence_id, version, relative_path and description"
            )
        for field in ("evidence_id", "version", "relative_path", "description"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise RAEIFindingError(f"supporting_evidence[{index}].{field} must be non-empty text")
        if item["evidence_id"] in seen_evidence:
            raise RAEIFindingError("finding evidence IDs must be unique")
        seen_evidence.add(item["evidence_id"])
        verified = verify_artifact(
            root, item["relative_path"], evidence_id=item["evidence_id"], version=item["version"]
        )
        supporting_refs.append({
            "evidence_id": verified.evidence_id,
            "relative_path": verified.relative_path,
            "version": verified.version,
            "sha256": verified.sha256,
            "size_bytes": verified.size_bytes,
            "description": item["description"].strip(),
        })

    suggested_level = (
        "E2" if supporting_refs else "E1" if reproduction_steps else "E0"
    )
    event_payload = {
        "finding_id": finding_id,
        "version": version,
        "project_id": project_id,
        "title": title,
        "affected_workflow": workflow,
        "expected_behavior": expected,
        "observed_behavior": observed,
        "impact": impact,
        "reproduction_step_count": len(reproduction_steps),
        "observation_evidence": primary_ref,
        "supporting_evidence": supporting_refs,
        "evidence_refs": [primary_ref, *supporting_refs],
        "observation_sha256": evidence.sha256,
        "suggested_evidence_level": suggested_level,
        "evidence_assessment_status": "NOT_ASSESSED",
        "source_authentication_status": "NOT_CHECKED",
        "claim_relevance_status": "NOT_ASSESSED",
        "identity_authentication_status": "UNVERIFIED",
        "status": "SUBMITTED",
        "tags": tags,
        "related_work_ids": related_work_ids,
        "supersedes": supersedes,
        "submitted_by_label": submitted_by,
        "redaction_note": redaction_note,
        "created_at_utc": payload["created_at_utc"],
    }
    event_id = f"FINDING:{finding_id}@{version}"
    identity_status = "UNVERIFIED"
    if any(value is not None for value in (verifier, submitter_credential, project_version, request_id)):
        if (not isinstance(verifier, ApprovalVerifier) or submitter_credential is None
                or not isinstance(project_version, str) or not project_version.strip()
                or not isinstance(request_id, str) or not request_id.strip()):
            raise RAEIFindingError("authenticated submitter capture requires verifier, V3 credential, project_version and request_id")
        artifact_binding = {
            "artifact_id": evidence.evidence_id,
            "artifact_version": evidence.version,
            "sha256": evidence.sha256,
            "size_bytes": evidence.size_bytes,
        }
        try:
            verified = verifier.verify_many_and_consume(
                (submitter_credential,),
                ({
                    "action": "FINDING_SUBMIT",
                    "project_id": project_id,
                    "project_version": project_version,
                    "request_id": request_id,
                    "artifact_binding": artifact_binding,
                },),
                require_distinct_actors=False,
            )[0]
            recorded = registry.append_authenticated_finding_capture_event(
                event_id, event_payload, project_id=project_id,
                project_version=project_version, request_id=request_id,
                approval=verified,
            )
        except (ApprovalError, ValueError, TypeError) as exc:
            raise RAEIFindingError(f"authenticated finding submission rejected: {exc}") from exc
        identity_status = "VERIFIED"
    else:
        recorded = registry.append_activity_event(
            event_id, "FINDING_CAPTURED", event_payload,
            project_id=project_id, subject_id=finding_id,
        )
    return {
        "recorded": recorded,
        "event_id": event_id,
        "finding_id": finding_id,
        "version": version,
        "status": "SUBMITTED",
        "suggested_evidence_level": suggested_level,
        "evidence_assessment_status": "NOT_ASSESSED",
        "identity_authentication_status": identity_status,
        "observation_sha256": evidence.sha256,
    }


def list_findings(
    registry: ReadinessRunRegistry, *, project_id: str | None = None
) -> list[dict[str, Any]]:
    """Return captured finding submissions; later dispositions remain separate events."""
    if not isinstance(registry, ReadinessRunRegistry):
        raise RAEIFindingError("a ReadinessRunRegistry is required")
    if project_id is not None and (not isinstance(project_id, str) or not project_id.strip()):
        raise RAEIFindingError("project_id must be null or non-empty text")
    results = []
    for event in registry.list_activity_events():
        if event["event_type"] != "FINDING_CAPTURED":
            continue
        if project_id is not None and event.get("project_id") != project_id:
            continue
        results.append({
            "sequence": event["sequence"],
            "event_id": event["event_id"],
            "event_hash": event["event_hash"],
            "recorded_at_utc": event["recorded_at_utc"],
            **event["payload"],
        })
    # Dispositions are a separately authenticated stream; capture remains immutable.
    from raei.governance import list_governed_reviews
    reviews = list_governed_reviews(
        registry, event_type="FINDING_DISPOSITIONED", project_id=project_id,
    )
    latest_by_version = {
        (item.get("subject_id"), item.get("payload", {}).get("finding_version")):
            item.get("payload", {})
        for item in reviews
    }
    for item in results:
        disposition = latest_by_version.get((item["finding_id"], item["version"]))
        item["status"] = disposition.get("disposition") if disposition else "SUBMITTED"
        if disposition:
            item["disposition_event_id"] = disposition.get("event_id")
            item["disposition_rationale"] = disposition.get("rationale")
            item["disposition_evidence_binding"] = disposition.get("evidence_binding")
    return results
