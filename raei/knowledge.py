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
SOURCE_TYPES = {"BIBLE", "OFFICIAL_DOC", "INTERNAL_SPEC", "CODE", "SECONDARY", "LESSON_FROM_FAILURE"}
AUTHORITY_LEVELS = {"SCRIPTURE", "OFFICIAL_PRIMARY", "INTERNAL_APPROVED", "SECONDARY", "UNVERIFIED"}


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
    if payload["source_type"] not in SOURCE_TYPES:
        raise RAEIKnowledgeError("unsupported source_type")
    if payload["authority_level"] not in AUTHORITY_LEVELS:
        raise RAEIKnowledgeError("unsupported authority_level")
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
        results.append(dict(payload))
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


def search_knowledge(
    registry: ReadinessRunRegistry, query: str, *, include_pending: bool = False
) -> list[dict[str, Any]]:
    if not isinstance(query, str) or not query.strip():
        raise RAEIKnowledgeError("search query must be a non-empty string")
    terms = [term for term in re.findall(r"[a-z0-9]+", query.lower()) if term]
    if not terms:
        return []
    matches = []
    for item in list_knowledge(registry):
        if item["status"] == "PENDING_REVIEW" and not include_pending:
            continue
        haystack = " ".join(
            [item["title"], item["summary"], *item["claims"], *item.get("tags", [])]
        ).lower()
        if all(term in haystack for term in terms):
            matches.append(item)
    return matches
