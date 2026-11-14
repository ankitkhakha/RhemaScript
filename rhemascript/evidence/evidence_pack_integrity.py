"""Bridge evidence-pack records to locally verified artefact bytes."""
from __future__ import annotations

import hmac
from pathlib import Path

from .artifact_verification import EvidenceIntegrityError, EvidenceVersion, verify_artifact, verify_json_artifact
import json
from .evidence_pack import EvidencePackError, ValidatedEvidencePack, validate_evidence_pack


class EvidencePackIntegrityError(EvidenceIntegrityError):
    """A validated pack cannot be reconciled with its local evidence bytes."""


def verify_pack_artifacts(pack: ValidatedEvidencePack, evidence_root: str | Path) -> tuple[EvidenceVersion, ...]:
    """Verify required bytes and Analytics payload semantics against exact source snapshots.

    Capability-referenced and approved artifacts are byte-verified. If an Analytics
    comparison is required, its two source snapshots are also verified and the
    comparison is recomputed from those exact snapshot payloads. A file hash alone
    does not establish semantic derivation.
    """
    if not isinstance(pack, ValidatedEvidencePack):
        raise EvidencePackIntegrityError("a validated evidence pack is required")
    # The dataclass is frozen only shallowly: callers can still mutate nested
    # dictionaries or construct one directly. Rebuild and revalidate a detached
    # manifest snapshot so this byte-verification boundary never trusts the
    # dataclass type or stale validation performed on earlier contents.
    try:
        pack = validate_evidence_pack({
            "manifest_id": pack.manifest_id,
            "schema_version": "1.0",
            "project_record": pack.project_record,
            "artifacts": list(pack.artifacts),
            "evidence_records": list(pack.evidence_records),
            "source_to_final_links": list(pack.source_to_final_links),
            "gate_records": list(pack.gate_records),
        })
    except (EvidencePackError, AttributeError, TypeError, ValueError) as exc:
        raise EvidencePackIntegrityError(
            "evidence pack failed structural revalidation"
        ) from exc

    artifacts_by_id = {artifact["artifact_id"]: artifact for artifact in pack.artifacts}
    referenced_ids = {
        artifact_id for record in pack.evidence_records
        for artifact_id in record.get("artifact_refs", [])
    }
    required_ids = {
        artifact["artifact_id"] for artifact in pack.artifacts
        if str(artifact.get("status", "")).upper() in {"VERIFIED", "APPROVED", "ACCEPTED"}
        or artifact["artifact_id"] in referenced_ids
    }

    # A required Analytics comparison depends on both exact source snapshots.
    for artifact_id in tuple(required_ids):
        artifact = artifacts_by_id[artifact_id]
        if artifact.get("artifact_type") == "YOUTUBE_ANALYTICS_COMPARISON":
            required_ids.add(artifact["current_snapshot_artifact_id"])
            required_ids.add(artifact["previous_snapshot_artifact_id"])

    versions: list[EvidenceVersion] = []
    analytics_payloads: dict[str, dict] = {}
    for artifact in pack.artifacts:
        artifact_id = artifact["artifact_id"]
        if artifact_id not in required_ids:
            continue

        status = str(artifact.get("status", "")).upper()
        local_path = artifact.get("local_path")
        expected_digest = artifact.get("sha256")
        if not isinstance(local_path, str) or not local_path.strip():
            raise EvidencePackIntegrityError(
                f"artifact {artifact_id} claims {status} without local_path"
            )
        if not isinstance(expected_digest, str) or len(expected_digest) != 64:
            raise EvidencePackIntegrityError(
                f"artifact {artifact_id} claims {status} without SHA-256"
            )

        artifact_type = artifact.get("artifact_type")
        try:
            if artifact_type in {"YOUTUBE_ANALYTICS_SNAPSHOT", "YOUTUBE_ANALYTICS_COMPARISON"}:
                actual, raw = verify_json_artifact(evidence_root, local_path)
                envelope = json.loads(raw)
                if (envelope.get("evidence_id") != artifact_id
                        or envelope.get("evidence_version") != artifact["version"]
                        or envelope.get("artifact_type") != artifact_type
                        or envelope.get("project_id") != artifact["project_id"]
                        or envelope.get("project_version") != artifact["project_version"]):
                    raise EvidencePackIntegrityError(
                        f"Analytics artifact {artifact_id} envelope does not match its manifest binding"
                    )
                payload = envelope.get("payload")
                if not isinstance(payload, dict):
                    raise EvidencePackIntegrityError(
                        f"Analytics artifact {artifact_id} payload must be an object"
                    )
                from rhemascript.integrations.youtube_analytics_evidence import (
                    YouTubeAnalyticsEvidenceError,
                    verify_analytics_evidence_snapshot,
                )
                from rhemascript.integrations.youtube_analytics_insights import (
                    YouTubeAnalyticsInsightError,
                    verify_analytics_period_comparison,
                )
                if artifact_type == "YOUTUBE_ANALYTICS_SNAPSHOT":
                    verify_analytics_evidence_snapshot(payload)
                    if payload.get("snapshot_sha256") != artifact.get("snapshot_sha256"):
                        raise EvidencePackIntegrityError(
                            f"Analytics snapshot {artifact_id} digest does not match its manifest metadata"
                        )
                else:
                    if payload.get("comparison_sha256") != artifact.get("comparison_sha256"):
                        raise EvidencePackIntegrityError(
                            f"Analytics comparison {artifact_id} digest does not match its manifest metadata"
                        )
                analytics_payloads[artifact_id] = payload
            else:
                actual = verify_artifact(
                    evidence_root, local_path, evidence_id=artifact_id,
                    version=artifact["version"],
                )
        except EvidenceIntegrityError as exc:
            raise EvidencePackIntegrityError(
                f"artifact {artifact_id} could not be byte-verified"
            ) from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise EvidencePackIntegrityError(
                f"Analytics artifact {artifact_id} payload could not be semantically verified"
            ) from exc

        if not hmac.compare_digest(actual.sha256, expected_digest.lower()):
            raise EvidencePackIntegrityError(
                f"artifact {artifact_id} content does not match declared SHA-256"
            )
        versions.append(actual)

    for artifact_id in required_ids:
        artifact = artifacts_by_id[artifact_id]
        if artifact.get("artifact_type") != "YOUTUBE_ANALYTICS_COMPARISON":
            continue
        current_id = artifact["current_snapshot_artifact_id"]
        previous_id = artifact["previous_snapshot_artifact_id"]
        current_snapshot = analytics_payloads.get(current_id)
        previous_snapshot = analytics_payloads.get(previous_id)
        comparison = analytics_payloads.get(artifact_id)
        if current_snapshot is None or previous_snapshot is None or comparison is None:
            raise EvidencePackIntegrityError(
                f"Analytics comparison {artifact_id} is missing its exact source snapshot bytes"
            )
        try:
            from rhemascript.integrations.youtube_analytics_insights import (
                verify_analytics_period_comparison,
            )
            verify_analytics_period_comparison(
                comparison, current_snapshot=current_snapshot,
                previous_snapshot=previous_snapshot,
            )
        except ValueError as exc:
            raise EvidencePackIntegrityError(
                f"Analytics comparison {artifact_id} does not derive from its exact source snapshots"
            ) from exc

    return tuple(versions)
