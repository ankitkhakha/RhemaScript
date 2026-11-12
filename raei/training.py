"""Evidence-linked RAEI practice and assessment orchestration.

An RAEI self-assessment can earn only PROVISIONAL_PASS. Independent review is
reserved until an authenticated human-approval credential is integrated.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from typing import Any

from rhemascript.evidence.artifact_verification import (
    EvidenceIntegrityError,
    EvidenceVersion,
    bind_assessment,
    is_verified_evidence_version,
    verify_assessment_binding,
)
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry

from .curriculum import CURRICULUM_VERSION, build_registry

SCHEMA = "raei-training-assessment-v1"
RECORD_TYPE = "RAEI_TRAINING_ATTEMPT_V1"
PASS_STATUSES = {"PROVISIONAL_PASS", "INDEPENDENTLY_REVIEWED"}
INDEPENDENT_STATUS = "INDEPENDENTLY_REVIEWED"


class RAEITrainingError(ValueError):
    """A curriculum, evidence, prerequisite or assessment rule was violated."""


def canonical_assessment_bytes(payload: dict[str, Any]) -> bytes:
    if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
        raise RAEITrainingError("assessment artifact must be a JSON object with string keys")
    try:
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RAEITrainingError("assessment artifact must contain canonical JSON values") from exc


def _units_by_id() -> dict[str, dict]:
    return {unit["id"]: unit for unit in build_registry()}


def get_progress(registry: ReadinessRunRegistry) -> dict[str, dict[str, Any]]:
    if not isinstance(registry, ReadinessRunRegistry):
        raise RAEITrainingError("a ReadinessRunRegistry is required")
    if not registry.verify():
        raise RAEITrainingError("learning registry integrity verification failed")
    progress: dict[str, dict[str, Any]] = {}
    for stored in registry.list_all():
        report = stored.get("report", {})
        if not isinstance(report, dict) or report.get("record_type") != RECORD_TYPE:
            continue
        unit_id = report.get("unit_id")
        if unit_id not in _units_by_id():
            raise RAEITrainingError("stored learning record references an unknown curriculum unit")
        progress[unit_id] = dict(report)
    return progress


def _prerequisites_met(unit: dict, progress: dict[str, dict[str, Any]]) -> bool:
    prerequisites = unit.get("prerequisites", [])
    if unit["domain"] == "integrated":
        return all(progress.get(item, {}).get("status") == INDEPENDENT_STATUS for item in prerequisites)
    return all(progress.get(item, {}).get("status") in PASS_STATUSES for item in prerequisites)


def next_unit(registry: ReadinessRunRegistry) -> dict | None:
    progress = get_progress(registry)
    for unit in build_registry():
        status = progress.get(unit["id"], {}).get("status")
        if status in PASS_STATUSES:
            continue
        if _prerequisites_met(unit, progress):
            return dict(unit)
    return None


def build_training_brief(unit_id: str, registry: ReadinessRunRegistry) -> dict[str, Any]:
    unit = _units_by_id().get(unit_id)
    if unit is None:
        raise RAEITrainingError(f"unknown curriculum unit: {unit_id}")
    progress = get_progress(registry)
    if not _prerequisites_met(unit, progress):
        raise RAEITrainingError("curriculum prerequisites are not yet satisfied")
    return {
        **unit,
        "assessment_schema": SCHEMA,
        "required_evidence": [
            "canonical assessment JSON artifact",
            "verified artifact ID, version and SHA-256 digest",
            "source code or study output, tests and execution result where applicable",
        ],
        "assessment_rules": {
            "criterion_scale": "integer 0 through 4",
            "pass_threshold": 3,
            "self_assessment_result": "PROVISIONAL_PASS only",
            "independent_review": "reserved for authenticated human approval integration",
            "critical_failure": "any critical failure requires NEEDS_REMEDIATION",
        },
        "authority_boundary": {
            "is_approval": False,
            "is_execution_authorisation": False,
            "permits_generation": False,
            "permits_publishing": False,
        },
    }


def record_attempt(
    registry: ReadinessRunRegistry,
    artifact_payload: dict[str, Any],
    evidence: EvidenceVersion,
) -> dict[str, Any]:
    """Record one self-assessment only when its canonical bytes match verified evidence."""
    if not is_verified_evidence_version(evidence):
        raise RAEITrainingError("assessment requires an exact EvidenceVersion from verify_artifact")
    encoded = canonical_assessment_bytes(artifact_payload)
    digest = hashlib.sha256(encoded).hexdigest()
    if digest != evidence.sha256:
        raise RAEITrainingError("assessment payload does not match the verified artifact bytes")

    required = {
        "schema", "curriculum_version", "attempt_id", "unit_id", "learner_id",
        "assessor_id", "assessor_role", "evidence_id", "evidence_version",
        "criterion_scores", "critical_failures", "assessor_note", "created_at_utc",
    }
    if not required.issubset(artifact_payload):
        raise RAEITrainingError("assessment artifact is missing required fields")
    if artifact_payload["schema"] != SCHEMA or artifact_payload["curriculum_version"] != CURRICULUM_VERSION:
        raise RAEITrainingError("assessment schema or curriculum version is unsupported")
    for field in ("attempt_id", "unit_id", "learner_id", "assessor_id", "evidence_id", "evidence_version"):
        value = artifact_payload[field]
        if not isinstance(value, str) or not value.strip():
            raise RAEITrainingError(f"{field} must be a non-empty string")
    if artifact_payload["evidence_id"] != evidence.evidence_id or artifact_payload["evidence_version"] != evidence.version:
        raise RAEITrainingError("assessment artifact does not identify the verified evidence version")
    if artifact_payload["learner_id"] != "RAEI" or artifact_payload["assessor_id"] != "RAEI" or artifact_payload["assessor_role"] != "RAEI_SELF":
        raise RAEITrainingError("this registry accepts RAEI self-assessments only; human review requires authenticated approval")
    try:
        created = datetime.fromisoformat(artifact_payload["created_at_utc"].replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise RAEITrainingError("created_at_utc must be an ISO-8601 timestamp") from exc
    if created.tzinfo is None or created.utcoffset() is None:
        raise RAEITrainingError("created_at_utc must include a timezone")

    unit = _units_by_id().get(artifact_payload["unit_id"])
    if unit is None:
        raise RAEITrainingError("assessment references an unknown curriculum unit")
    progress = get_progress(registry)
    if progress.get(unit["id"], {}).get("status") == INDEPENDENT_STATUS:
        raise RAEITrainingError("independently reviewed units are immutable; create a versioned curriculum revision")
    if not _prerequisites_met(unit, progress):
        raise RAEITrainingError("curriculum prerequisites are not yet satisfied")

    scores = artifact_payload["criterion_scores"]
    if not isinstance(scores, dict) or set(scores) != set(unit["rubric"]):
        raise RAEITrainingError("criterion_scores must contain exactly the unit rubric criteria")
    for criterion, score in scores.items():
        if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 4:
            raise RAEITrainingError(f"{criterion} must be an integer from 0 through 4")
    critical_failures = artifact_payload["critical_failures"]
    if (not isinstance(critical_failures, list)
            or any(not isinstance(item, str) or not item.strip() for item in critical_failures)):
        raise RAEITrainingError("critical_failures must be a list of non-empty strings")
    assessor_note = artifact_payload["assessor_note"]
    if not isinstance(assessor_note, str):
        raise RAEITrainingError("assessor_note must be a string")

    overall_score = min(scores.values())
    status = "NEEDS_REMEDIATION" if overall_score < 3 or critical_failures else "PROVISIONAL_PASS"
    binding = bind_assessment(artifact_payload["attempt_id"], evidence, overall_score)
    if not verify_assessment_binding(binding, evidence):
        raise RAEITrainingError("assessment binding did not verify against the exact evidence version")

    report = {
        "record_type": RECORD_TYPE,
        "curriculum_version": CURRICULUM_VERSION,
        "unit_id": unit["id"],
        "attempt_id": artifact_payload["attempt_id"],
        "learner_id": "RAEI",
        "assessor_id": "RAEI",
        "assessor_role": "RAEI_SELF",
        "created_at_utc": artifact_payload["created_at_utc"],
        "criterion_scores": dict(scores),
        "overall_score": overall_score,
        "critical_failures": list(critical_failures),
        "assessor_note": assessor_note,
        "status": status,
        "assessment_binding": binding,
        "assessment_is_approval": False,
        "assessment_is_execution_authorisation": False,
    }
    registry.record(artifact_payload["attempt_id"], report, (evidence,), ())
    return report
