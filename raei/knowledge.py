"""Versioned, evidence-bound RAEI knowledge intake.

Intake is always PENDING_REVIEW. RAEI cannot approve its own knowledge.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re
from typing import Any

from rhemascript.evidence.artifact_verification import EvidenceVersion, is_verified_evidence_version
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry

SCHEMA = "raei-knowledge-item-v1"
RECORD_TYPE = "RAEI_KNOWLEDGE_ITEM_V1"
_ID = re.compile(r"^[A-Z0-9][A-Z0-9._:-]{2,127}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
SOURCE_TYPES = {"BIBLE", "OFFICIAL_DOC", "INTERNAL_SPEC", "CODE", "SECONDARY", "LESSON_FROM_FAILURE", "RAEI_CLOSED_FINDING"}
AUTHORITY_LEVELS = {"SCRIPTURE", "OFFICIAL_PRIMARY", "INTERNAL_APPROVED", "SECONDARY", "UNVERIFIED"}
SOURCE_AUTHORITY = {"BIBLE": "SCRIPTURE", "OFFICIAL_DOC": "OFFICIAL_PRIMARY", "INTERNAL_SPEC": "UNVERIFIED", "CODE": "UNVERIFIED", "SECONDARY": "SECONDARY", "LESSON_FROM_FAILURE": "UNVERIFIED", "RAEI_CLOSED_FINDING": "UNVERIFIED"}


class RAEIKnowledgeError(ValueError):
    """Knowledge intake, provenance or approval-boundary violation."""


def canonical_knowledge_bytes(payload: dict[str, Any]) -> bytes:
    if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
        raise RAEIKnowledgeError("knowledge artifact must be a JSON object with string keys")
    try:
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RAEIKnowledgeError("knowledge artifact must contain canonical JSON values") from exc


def _required_text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RAEIKnowledgeError(f"{field} must be a non-empty string")
    return value.strip()


def _string_list(payload: dict[str, Any], field: str, *, required: bool = False) -> list[str]:
    value = payload.get(field)
    if value is None and not required:
        return []
    if not isinstance(value, list) or (required and not value):
        raise RAEIKnowledgeError(f"{field} must be a {'non-empty ' if required else ''}list of strings")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise RAEIKnowledgeError(f"{field} must contain only non-empty strings")
    return value


def _validate_payload(payload: dict[str, Any], evidence: EvidenceVersion) -> None:
    required = {
        "schema", "knowledge_id", "version", "title", "domain", "source_type",
        "authority_level", "source_name", "source_version", "source_reference",
        "summary", "claims", "limitations", "tags", "evidence_id", "evidence_version",
        "status", "source_authentication_status", "claim_relevance_status", "created_at_utc",
    }
    if not required.issubset(payload):
        raise RAEIKnowledgeError("knowledge artifact is missing required fields")
    if payload["schema"] != SCHEMA:
        raise RAEIKnowledgeError("unsupported knowledge schema")
    if not isinstance(payload["knowledge_id"], str) or not _ID.fullmatch(payload["knowledge_id"]):
        raise RAEIKnowledgeError("knowledge_id must be a stable uppercase identifier")
    if not isinstance(payload["version"], str) or not _VERSION.fullmatch(payload["version"]):
        raise RAEIKnowledgeError("version must use numeric major.minor[.patch] format")
    for field in ("title", "domain", "source_name", "source_version", "source_reference", "summary"):
        _required_text(payload, field)
    if not isinstance(payload["source_type"], str) or payload["source_type"] not in SOURCE_TYPES:
        raise RAEIKnowledgeError("unsupported source_type")
    if not isinstance(payload["authority_level"], str) or payload["authority_level"] not in AUTHORITY_LEVELS:
        raise RAEIKnowledgeError("unsupported authority_level")
    if payload["authority_level"] != SOURCE_AUTHORITY[payload["source_type"]]:
        raise RAEIKnowledgeError("authority_level does not match the declared source_type")
    if payload["status"] != "PENDING_REVIEW":
        raise RAEIKnowledgeError("new knowledge can only enter as PENDING_REVIEW")
    if payload["source_authentication_status"] != "NOT_CHECKED":
        raise RAEIKnowledgeError("content hash verification cannot assert source authentication")
    if payload["claim_relevance_status"] != "NOT_ASSESSED":
        raise RAEIKnowledgeError("content hash verification cannot assert claim relevance")
    _string_list(payload, "claims", required=True)
    _string_list(payload, "limitations")
    _string_list(payload, "tags")
    supersedes = _string_list(payload, "supersedes")
    if any(not re.fullmatch(r"[A-Z0-9][A-Z0-9._:-]{2,127}@[0-9]+\.[0-9]+(?:\.[0-9]+)?", item) for item in supersedes):
        raise RAEIKnowledgeError("supersedes entries must use knowledge_id@version format")
    if payload["evidence_id"] != evidence.evidence_id or payload["evidence_version"] != evidence.version:
        raise RAEIKnowledgeError("knowledge artifact does not identify the verified evidence version")
    created_at = payload["created_at_utc"]
    if not isinstance(created_at, str):
        raise RAEIKnowledgeError("created_at_utc must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RAEIKnowledgeError("created_at_utc must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RAEIKnowledgeError("created_at_utc must include a timezone")

    if payload["source_type"] == "BIBLE":
        language = _required_text(payload, "language")
        translation = _required_text(payload, "translation_version")
        _required_text(payload, "book")
        _required_text(payload, "passage")
        direct_quote = payload.get("direct_scripture_quote")
        if not isinstance(direct_quote, bool):
            raise RAEIKnowledgeError("direct_scripture_quote must be explicitly boolean")
        if language.lower() in {"hi", "hindi"} and direct_quote and translation != "HINOVBSI":
            raise RAEIKnowledgeError("direct Hindi Scripture quotations must use the approved HINOVBSI wording")

    if payload["source_type"] == "LESSON_FROM_FAILURE":
        for field in ("failure_attempt_id", "root_cause", "remediation"):
            _required_text(payload, field)
        _string_list(payload, "regression_test_refs", required=True)
        _string_list(payload, "affected_unit_ids", required=True)


def _validate_inherited_lineage(registry: ReadinessRunRegistry, payload: dict[str, Any]) -> None:
    finding_id = payload.get("source_finding_id")
    finding_version = payload.get("source_finding_version")
    lineage = payload.get("source_lifecycle_lineage")
    if (not isinstance(finding_id, str) or not finding_id.strip()
            or not isinstance(finding_version, str) or not finding_version.strip()
            or not isinstance(lineage, dict)):
        raise RAEIKnowledgeError("stored inherited knowledge lineage is malformed")
    events = {event["event_id"]: event for event in registry.list_activity_events()}
    fields = (
        ("plan_event_id", "FINDING_PLANNED"),
        ("implementation_event_id", "FINDING_IMPLEMENTED"),
        ("effectiveness_event_id", "FINDING_EFFECTIVENESS_ASSESSED"),
        ("closure_event_id", "FINDING_CLOSED"),
    )
    selected = {}
    for field, event_type in fields:
        event = events.get(lineage.get(field))
        if (not event or event.get("event_type") != event_type
                or event.get("subject_id") != finding_id
                or event.get("payload", {}).get("finding_version") != finding_version):
            raise RAEIKnowledgeError("stored inherited knowledge references an invalid source lifecycle event")
        selected[field] = event
    closure_auth = selected["closure_event_id"].get("payload", {}).get("authorization", {})
    closure_project = selected["closure_event_id"].get("project_id")
    closure_version = closure_auth.get("project_version")
    if (not isinstance(closure_project, str) or not closure_project
            or not isinstance(closure_version, str) or not closure_version
            or any(
                event.get("project_id") != closure_project
                or event.get("payload", {}).get("authorization", {}).get("project_version") != closure_version
                for event in selected.values()
            )):
        raise RAEIKnowledgeError("stored inherited knowledge crosses project or project-version lifecycle scope")
    plan = selected["plan_event_id"]
    implementation = selected["implementation_event_id"]
    effectiveness = selected["effectiveness_event_id"]
    closure = selected["closure_event_id"]
    expected = {
        "plan_event_id": plan["event_id"],
        "implementation_event_id": implementation["event_id"],
        "effectiveness_event_id": effectiveness["event_id"],
        "closure_event_id": closure["event_id"],
        "plan_evidence_binding": plan["payload"].get("evidence_binding"),
        "implementation_evidence_binding": implementation["payload"].get("evidence_binding"),
        "effectiveness_evidence_binding": effectiveness["payload"].get("evidence_binding"),
    }
    if (lineage != expected
            or effectiveness["payload"].get("outcome") != "EFFECTIVE"
            or closure["payload"].get("closure_decision") != "CLOSED"
            or closure["payload"].get("evidence_binding") != effectiveness["payload"].get("evidence_binding")
            or closure["payload"].get("lifecycle_lineage") != {
                "plan_event_id": plan["event_id"],
                "implementation_event_id": implementation["event_id"],
                "effectiveness_event_id": effectiveness["event_id"],
            }):
        raise RAEIKnowledgeError("stored inherited knowledge is detached from its exact closed finding lineage")


def list_knowledge(registry: ReadinessRunRegistry) -> list[dict[str, Any]]:
    if not isinstance(registry, ReadinessRunRegistry) or not registry.verify():
        raise RAEIKnowledgeError("knowledge registry integrity verification failed")
    results = []
    for stored in registry.list_all():
        report = stored.get("report", {})
        if not isinstance(report, dict) or report.get("record_type") != RECORD_TYPE:
            continue
        payload = report.get("knowledge_payload")
        evidence_items = stored.get("byte_verified_evidence")
        binding = report.get("evidence_binding")
        if not isinstance(payload, dict) or not isinstance(evidence_items, list) or len(evidence_items) != 1 or not isinstance(binding, dict):
            raise RAEIKnowledgeError("stored knowledge record lacks one exact evidence binding")
        evidence_item = evidence_items[0]
        if not isinstance(evidence_item, dict):
            raise RAEIKnowledgeError("stored knowledge evidence record is malformed")
        try:
            evidence_stub = EvidenceVersion(
                evidence_item["evidence_id"], evidence_item["relative_path"],
                evidence_item["version"], evidence_item["sha256"], evidence_item["size_bytes"],
            )
            _validate_payload(payload, evidence_stub)
        except (KeyError, TypeError, RAEIKnowledgeError) as exc:
            # Preserve the specific failed invariant for operators and regression tests.
            raise RAEIKnowledgeError(
                f"stored knowledge payload failed schema validation: {exc}"
            ) from exc
        encoded = canonical_knowledge_bytes(payload)
        digest = hashlib.sha256(encoded).hexdigest()
        if (stored.get("run_id") != f"KNOWLEDGE:{payload.get('knowledge_id')}:{payload.get('version')}"
                or payload.get("status") != "PENDING_REVIEW"
                or payload.get("source_authentication_status") != "NOT_CHECKED"
                or payload.get("claim_relevance_status") != "NOT_ASSESSED"
                or not isinstance(evidence_item, dict)
                or binding.get("evidence_id") != evidence_item.get("evidence_id")
                or binding.get("evidence_version") != evidence_item.get("version")
                or binding.get("evidence_sha256") != evidence_item.get("sha256")
                or binding.get("evidence_sha256") != digest
                or payload.get("evidence_id") != evidence_item.get("evidence_id")
                or payload.get("evidence_version") != evidence_item.get("version")):
            raise RAEIKnowledgeError("stored knowledge status or evidence provenance was altered")
        if payload.get("source_type") == "RAEI_CLOSED_FINDING":
            _validate_inherited_lineage(registry, payload)
        results.append(dict(payload))
    # Review events are a separate, signed governance stream. The immutable
    # intake record remains PENDING_REVIEW; this projection never rewrites it.
    from raei.governance import list_governed_reviews
    reviews = list_governed_reviews(registry, event_type="KNOWLEDGE_REVIEWED")
    latest_by_version = {
        (item.get("subject_id"), item.get("payload", {}).get("knowledge_version")):
            item.get("payload", {}).get("decision")
        for item in reviews
    }
    for item in results:
        decision = latest_by_version.get((item["knowledge_id"], item["version"]))
        item["review_status"] = decision or "PENDING_REVIEW"
        item["status"] = decision or "PENDING_REVIEW"
    return results


def record_knowledge(
    registry: ReadinessRunRegistry,
    payload: dict[str, Any],
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    if not is_verified_evidence_version(evidence):
        raise RAEIKnowledgeError("knowledge intake requires an exact EvidenceVersion from verify_artifact")
    encoded = canonical_knowledge_bytes(payload)
    digest = hashlib.sha256(encoded).hexdigest()
    if digest != evidence.sha256:
        raise RAEIKnowledgeError("knowledge payload does not match the verified artifact bytes")
    _validate_payload(payload, evidence)
    existing = list_knowledge(registry)
    known_versions = {f"{item['knowledge_id']}@{item['version']}" for item in existing}
    for superseded in _string_list(payload, "supersedes"):
        if superseded not in known_versions:
            raise RAEIKnowledgeError(f"superseded knowledge version does not exist: {superseded}")
    run_id = f"KNOWLEDGE:{payload['knowledge_id']}:{payload['version']}"
    report = {
        "record_type": RECORD_TYPE,
        "knowledge_payload": dict(payload),
        "evidence_binding": {
            "evidence_id": evidence.evidence_id,
            "evidence_version": evidence.version,
            "evidence_sha256": evidence.sha256,
        },
        "assessment_is_approval": False,
        "assessment_is_execution_authorisation": False,
    }
    registry.record(run_id, report, (evidence,), ())
    return report



def inherit_closed_finding_as_knowledge(
    registry: ReadinessRunRegistry,
    payload: dict[str, Any],
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Register a proposed knowledge item only from a closed, effective finding lineage.

    The inherited item remains PENDING_REVIEW, source authentication NOT_CHECKED,
    claim relevance NOT_ASSESSED and authority UNVERIFIED.
    """
    if not isinstance(registry, ReadinessRunRegistry) or not registry.verify():
        raise RAEIKnowledgeError("closed-finding inheritance requires a valid registry")
    if not isinstance(payload, dict) or payload.get("source_type") != "RAEI_CLOSED_FINDING":
        raise RAEIKnowledgeError("inheritance requires source_type RAEI_CLOSED_FINDING")
    finding_id = payload.get("source_finding_id")
    finding_version = payload.get("source_finding_version")
    lineage = payload.get("source_lifecycle_lineage")
    if (not isinstance(finding_id, str) or not finding_id.strip()
            or not isinstance(finding_version, str) or not finding_version.strip()
            or not isinstance(lineage, dict)
            or set(lineage) != {
                "plan_event_id", "implementation_event_id", "effectiveness_event_id",
                "closure_event_id", "plan_evidence_binding",
                "implementation_evidence_binding", "effectiveness_evidence_binding",
            }):
        raise RAEIKnowledgeError("inherited knowledge must carry complete source finding lineage")
    events = {
        event["event_id"]: event for event in registry.list_activity_events()
        if event.get("project_id") is not None
    }
    plan = events.get(lineage["plan_event_id"])
    implementation = events.get(lineage["implementation_event_id"])
    effectiveness = events.get(lineage["effectiveness_event_id"])
    closure = events.get(lineage["closure_event_id"])
    expected = (
        (plan, "FINDING_PLANNED"),
        (implementation, "FINDING_IMPLEMENTED"),
        (effectiveness, "FINDING_EFFECTIVENESS_ASSESSED"),
        (closure, "FINDING_CLOSED"),
    )
    if any(event is None or event.get("event_type") != kind for event, kind in expected):
        raise RAEIKnowledgeError("inherited knowledge references missing or wrong lifecycle events")
    for event, _ in expected:
        event_payload = event.get("payload", {})
        if (event.get("subject_id") != finding_id
                or event_payload.get("finding_id") != finding_id
                or event_payload.get("finding_version") != finding_version):
            raise RAEIKnowledgeError("inherited knowledge source events do not match the exact finding version")
    closure_auth = closure.get("payload", {}).get("authorization", {})
    closure_project = closure.get("project_id")
    closure_version = closure_auth.get("project_version")
    if (not isinstance(closure_project, str) or not closure_project
            or not isinstance(closure_version, str) or not closure_version
            or any(
                event.get("project_id") != closure_project
                or event.get("payload", {}).get("authorization", {}).get("project_version") != closure_version
                for event, _ in expected
            )):
        raise RAEIKnowledgeError("knowledge inheritance crosses project or project-version lifecycle scope")
    if (effectiveness["payload"].get("outcome") != "EFFECTIVE"
            or closure["payload"].get("closure_decision") != "CLOSED"
            or closure["payload"].get("evidence_binding") != effectiveness["payload"].get("evidence_binding")
            or closure["payload"].get("lifecycle_lineage") != {
                "plan_event_id": plan["event_id"],
                "implementation_event_id": implementation["event_id"],
                "effectiveness_event_id": effectiveness["event_id"],
            }):
        raise RAEIKnowledgeError("knowledge inheritance requires a closed finding with effective, exact evidence lineage")
    expected_lineage = {
        "plan_event_id": plan["event_id"],
        "implementation_event_id": implementation["event_id"],
        "effectiveness_event_id": effectiveness["event_id"],
        "closure_event_id": closure["event_id"],
        "plan_evidence_binding": plan["payload"].get("evidence_binding"),
        "implementation_evidence_binding": implementation["payload"].get("evidence_binding"),
        "effectiveness_evidence_binding": effectiveness["payload"].get("evidence_binding"),
    }
    if lineage != expected_lineage:
        raise RAEIKnowledgeError("inherited knowledge lineage differs from the verified closed finding history")
    if (payload.get("authority_level") != "UNVERIFIED"
            or payload.get("source_authentication_status") != "NOT_CHECKED"
            or payload.get("claim_relevance_status") != "NOT_ASSESSED"
            or payload.get("status") != "PENDING_REVIEW"):
        raise RAEIKnowledgeError("inherited knowledge cannot self-promote authority, source authentication or review status")
    for field in ("learning_scope", "confidence_level", "review_due_utc"):
        _required_text(payload, field)
    _string_list(payload, "applicability_conditions", required=True)
    _string_list(payload, "known_counterexamples")
    return record_knowledge(registry, payload, evidence)


def search_knowledge(
    registry: ReadinessRunRegistry, query: str, *, include_pending: bool = False
) -> list[dict[str, Any]]:
    if not isinstance(query, str) or not query.strip():
        raise RAEIKnowledgeError("search query must be a non-empty string")
    terms = [term for term in re.findall(r"[^\W_]+", query.lower(), flags=re.UNICODE) if term]
    if not terms:
        return []
    matches = []
    for item in list_knowledge(registry):
        if item["status"] != "APPROVED" and not include_pending:
            continue
        haystack = " ".join(
            [item["title"], item["summary"], item["domain"], item["source_type"],
             *item["claims"], *item.get("tags", [])]
        ).lower()
        if all(term in haystack for term in terms):
            matches.append(item)
    return matches
