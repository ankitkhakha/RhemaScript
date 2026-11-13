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
    # Validate persisted submitter identity envelopes before projecting any finding.
    for item in results:
        identity_status = item.get("identity_authentication_status")
        submitter = item.get("submitter_identity")
        authorization = item.get("submitter_authorization")
        primary = item.get("observation_evidence", {})
        if identity_status == "VERIFIED":
            if (not isinstance(submitter, dict) or not isinstance(authorization, dict)
                    or authorization.get("action") != "FINDING_SUBMIT"
                    or authorization.get("project_id") != item.get("project_id")
                    or authorization.get("artifact_sha256") != primary.get("sha256")
                    or authorization.get("artifact_size_bytes") != primary.get("size_bytes")
                    or not isinstance(authorization.get("approval_id"), str)
                    or not isinstance(authorization.get("signature_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", authorization["signature_sha256"])
                    or not isinstance(submitter.get("subject_id"), str)
                    or not isinstance(submitter.get("actor_id"), str)
                    or not isinstance(submitter.get("identity_session_id"), str)
                    or not isinstance(submitter.get("identity_policy_version"), str)
                    or not isinstance(submitter.get("identity_provider_id"), str)):
                raise RAEIFindingError("stored authenticated submitter envelope is invalid")
            if (authorization.get("approval_id") == ""
                    or authorization.get("request_id") == ""
                    or authorization.get("project_version") == ""):
                raise RAEIFindingError("stored submitter authorization scope is incomplete")
        elif identity_status == "UNVERIFIED":
            if submitter is not None or authorization is not None:
                raise RAEIFindingError("unverified finding cannot carry submitter identity claims")
        else:
            raise RAEIFindingError("stored finding identity authentication status is invalid")

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
    finding_by_version = {(entry["finding_id"], entry["version"]): entry for entry in results}
    lifecycle_events = [
        event for event in registry.list_activity_events()
        if event["event_type"] in {"FINDING_RESEARCHED", "FINDING_REPRODUCED", "FINDING_PLANNED", "FINDING_IMPLEMENTED", "FINDING_EFFECTIVENESS_ASSESSED"}
    ]
    latest_research = {}
    latest_reproduction = {}
    latest_plan = {}
    latest_implementation = {}
    latest_effectiveness = {}
    for event in lifecycle_events:
        payload = event.get("payload", {})
        key = (event.get("subject_id"), payload.get("finding_version"))
        expected_action = {
            "FINDING_RESEARCHED": "FINDING_RESEARCH",
            "FINDING_REPRODUCED": "FINDING_REPRODUCE",
            "FINDING_PLANNED": "FINDING_PLAN",
            "FINDING_IMPLEMENTED": "FINDING_IMPLEMENT",
            "FINDING_EFFECTIVENESS_ASSESSED": "FINDING_EFFECTIVENESS_ASSESS",
        }[event["event_type"]]
        auth = payload.get("authorization")
        binding = payload.get("evidence_binding")
        refs = payload.get("evidence_refs")
        if (not isinstance(auth, dict) or auth.get("action") != expected_action
                or auth.get("project_id") != event.get("project_id")
                or not all(isinstance(auth.get(field), str) and auth[field].strip()
                           for field in ("issuer", "approval_id", "actor_id", "subject_id",
                                         "actor_role", "identity_provider_id",
                                         "identity_policy_version", "identity_session_id",
                                         "project_version", "request_id"))
                or not isinstance(auth.get("signature_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", auth["signature_sha256"])
                or not isinstance(binding, dict)
                or auth.get("artifact_sha256") != binding.get("sha256")
                or auth.get("artifact_size_bytes") != binding.get("size_bytes")
                or not isinstance(refs, list) or len(refs) != 1 or not isinstance(refs[0], dict)
                or refs[0].get("evidence_id") != binding.get("evidence_id")
                or refs[0].get("version") != binding.get("evidence_version")
                or refs[0].get("sha256") != binding.get("sha256")
                or refs[0].get("size_bytes") != binding.get("size_bytes")
                or payload.get("finding_id") != event.get("subject_id")):
            raise RAEIFindingError("stored authenticated finding lifecycle envelope is invalid")
        for timestamp_field in ("created_at_utc",):
            try:
                parsed = datetime.fromisoformat(payload[timestamp_field].replace("Z", "+00:00"))
            except (KeyError, AttributeError, TypeError, ValueError) as exc:
                raise RAEIFindingError("stored lifecycle timestamp is invalid") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise RAEIFindingError("stored lifecycle timestamp must include a timezone")
        if event["event_type"] == "FINDING_RESEARCHED":
            if key in latest_research or key in latest_reproduction or key in latest_plan:
                raise RAEIFindingError("finding research history contains a duplicate or out-of-order event")
            latest_research[key] = event
        elif event["event_type"] == "FINDING_REPRODUCED":
            if key not in latest_research or key in latest_reproduction or key in latest_plan:
                raise RAEIFindingError("finding reproduction history is missing research or is duplicated")
            research_auth = latest_research[key]["payload"]["authorization"]
            if (auth.get("subject_id") == research_auth.get("subject_id")
                    or auth.get("identity_session_id") == research_auth.get("identity_session_id")
                    or auth.get("identity_provider_id") != research_auth.get("identity_provider_id")
                    or auth.get("identity_policy_version") != research_auth.get("identity_policy_version")):
                raise RAEIFindingError("finding reproduction is not independently authenticated")
            latest_reproduction[key] = event
        elif event["event_type"] == "FINDING_PLANNED":
            if (key not in latest_research or key not in latest_reproduction or key in latest_plan
                    or latest_reproduction[key]["payload"].get("outcome") != "REPRODUCED"):
                raise RAEIFindingError("finding plan is missing prior research/reproduction or is duplicated")
            disposition = latest_by_version.get(key)
            if not disposition or disposition.get("disposition") != "ACCEPTED":
                raise RAEIFindingError("finding plan requires an accepted governed disposition")
            prior_auth = [
                latest_research[key]["payload"]["authorization"],
                latest_reproduction[key]["payload"]["authorization"],
            ]
            captured_finding = finding_by_version.get(key, {})
            if captured_finding.get("submitter_identity"):
                prior_auth.append(captured_finding["submitter_identity"])
            if any(
                auth.get("subject_id") == prior.get("subject_id")
                or auth.get("identity_session_id") == prior.get("identity_session_id")
                or auth.get("identity_provider_id") != prior.get("identity_provider_id")
                or auth.get("identity_policy_version") != prior.get("identity_policy_version")
                for prior in prior_auth
            ):
                raise RAEIFindingError("finding plan is not independently authenticated")
            latest_plan[key] = event
        elif event["event_type"] == "FINDING_IMPLEMENTED":
            if key not in latest_plan or key in latest_implementation:
                raise RAEIFindingError("finding implementation is missing an approved plan or is duplicated")
            plan_payload = latest_plan[key]["payload"]
            if (payload.get("plan_event_id") != latest_plan[key]["event_id"]
                    or payload.get("plan_evidence_binding") != plan_payload.get("evidence_binding")):
                raise RAEIFindingError("finding implementation does not bind the exact approved plan")
            impl_binding = payload.get("evidence_binding")
            impl_refs = payload.get("evidence_refs")
            if (not isinstance(impl_binding, dict)
                    or not isinstance(impl_refs, list) or len(impl_refs) != 1
                    or not isinstance(impl_refs[0], dict)
                    or impl_refs[0].get("evidence_id") != impl_binding.get("evidence_id")
                    or impl_refs[0].get("version") != impl_binding.get("evidence_version")
                    or impl_refs[0].get("sha256") != impl_binding.get("sha256")
                    or impl_refs[0].get("size_bytes") != impl_binding.get("size_bytes")):
                raise RAEIFindingError("finding implementation evidence binding is invalid")
            prior_auth = [
                latest_research[key]["payload"]["authorization"],
                latest_reproduction[key]["payload"]["authorization"],
                latest_plan[key]["payload"]["authorization"],
            ]
            captured_finding = finding_by_version.get(key, {})
            if captured_finding.get("submitter_identity"):
                prior_auth.append(captured_finding["submitter_identity"])
            if any(
                auth.get("subject_id") == prior.get("subject_id")
                or auth.get("identity_session_id") == prior.get("identity_session_id")
                or auth.get("identity_provider_id") != prior.get("identity_provider_id")
                or auth.get("identity_policy_version") != prior.get("identity_policy_version")
                for prior in prior_auth
            ):
                raise RAEIFindingError("finding implementation is not independently authenticated")
            latest_implementation[key] = event
        else:
            if key not in latest_implementation or key in latest_effectiveness:
                raise RAEIFindingError("effectiveness assessment is missing implementation or is duplicated")
            implementation = latest_implementation[key]
            if (payload.get("implementation_event_id") != implementation["event_id"]
                    or payload.get("implementation_evidence_binding") != implementation["payload"].get("evidence_binding")
                    or payload.get("outcome") not in {"EFFECTIVE", "INEFFECTIVE", "INCONCLUSIVE"}):
                raise RAEIFindingError("effectiveness assessment does not bind the exact implementation or has an invalid outcome")
            criteria = payload.get("criteria_results")
            outcomes = payload.get("observed_outcomes")
            if (not isinstance(criteria, list) or not criteria
                    or not isinstance(outcomes, list) or not outcomes
                    or any(not isinstance(value, str) or not value.strip() for value in criteria + outcomes)):
                raise RAEIFindingError("effectiveness assessment is missing criterion results or observed outcomes")
            prior_auth = [
                latest_research[key]["payload"]["authorization"],
                latest_reproduction[key]["payload"]["authorization"],
                latest_plan[key]["payload"]["authorization"],
                implementation["payload"]["authorization"],
            ]
            captured_finding = finding_by_version.get(key, {})
            if captured_finding.get("submitter_identity"):
                prior_auth.append(captured_finding["submitter_identity"])
            if any(
                auth.get("subject_id") == prior.get("subject_id")
                or auth.get("identity_session_id") == prior.get("identity_session_id")
                or auth.get("identity_provider_id") != prior.get("identity_provider_id")
                or auth.get("identity_policy_version") != prior.get("identity_policy_version")
                for prior in prior_auth
            ):
                raise RAEIFindingError("effectiveness assessor is not independently authenticated")
            latest_effectiveness[key] = event
    for item in results:
        key = (item["finding_id"], item["version"])
        disposition = latest_by_version.get(key)
        research = latest_research.get(key)
        reproduction = latest_reproduction.get(key)
        plan = latest_plan.get(key)
        implementation = latest_implementation.get(key)
        effectiveness = latest_effectiveness.get(key)
        if effectiveness:
            item["status"] = effectiveness["payload"]["outcome"]
            item["effectiveness_event_id"] = effectiveness["event_id"]
            item["effectiveness_evidence_binding"] = effectiveness["payload"].get("evidence_binding")
            item["implementation_event_id"] = effectiveness["payload"].get("implementation_event_id")
        elif implementation:
            item["status"] = "IMPLEMENTED"
            item["implementation_event_id"] = implementation["event_id"]
            item["implementation_evidence_binding"] = implementation["payload"].get("evidence_binding")
            item["plan_event_id"] = implementation["payload"].get("plan_event_id")
        elif plan:
            item["status"] = "PLANNED"
            item["plan_event_id"] = plan["event_id"]
            item["plan_evidence_binding"] = plan["payload"].get("evidence_binding")
        elif disposition:
            item["status"] = disposition.get("disposition")
            item["disposition_event_id"] = disposition.get("event_id")
            item["disposition_rationale"] = disposition.get("rationale")
            item["disposition_evidence_binding"] = disposition.get("evidence_binding")
        elif reproduction:
            item["status"] = reproduction["payload"].get("outcome", "REPRODUCED")
            item["reproduction_event_id"] = reproduction["event_id"]
            item["reproduction_evidence_binding"] = reproduction["payload"].get("evidence_binding")
            item["reproduction_outcome"] = reproduction["payload"].get("outcome")
        elif research:
            item["status"] = "RESEARCHED"
            item["research_event_id"] = research["event_id"]
            item["research_evidence_binding"] = research["payload"].get("evidence_binding")
        else:
            item["status"] = "SUBMITTED"
    return results
