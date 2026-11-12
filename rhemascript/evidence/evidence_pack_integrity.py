"""Bridge evidence-pack records to locally verified artefact bytes."""
from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any

from .artifact_verification import EvidenceIntegrityError, EvidenceVersion, verify_artifact
from .evidence_pack import ValidatedEvidencePack


class EvidencePackIntegrityError(EvidenceIntegrityError):
    pass


def verify_pack_artifacts(pack: ValidatedEvidencePack, evidence_root: str | Path) -> tuple[EvidenceVersion, ...]:
    """Require byte-level proof for every artifact the pack labels verified/approved.

    Artifact records must carry local_path and sha256. These are checked against
    the file bytes; caller-provided status strings are never treated as proof.
    """
    if not isinstance(pack, ValidatedEvidencePack):
        raise EvidencePackIntegrityError("a validated evidence pack is required")
    versions = []
    for artifact in pack.artifacts:
        status = str(artifact.get("status", "")).upper()
        if status not in {"VERIFIED", "APPROVED", "ACCEPTED"}:
            continue
        local_path = artifact.get("local_path")
        expected_digest = artifact.get("sha256")
        if not isinstance(local_path, str) or not local_path.strip():
            raise EvidencePackIntegrityError(
                f"artifact {artifact['artifact_id']} claims {status} without local_path"
            )
        if not isinstance(expected_digest, str) or len(expected_digest) != 64:
            raise EvidencePackIntegrityError(
                f"artifact {artifact['artifact_id']} claims {status} without SHA-256"
            )
        actual = verify_artifact(
            evidence_root, local_path, evidence_id=artifact["artifact_id"],
            version=artifact["version"],
        )
        if not hmac.compare_digest(actual.sha256, expected_digest.lower()):
            raise EvidencePackIntegrityError(
                f"artifact {artifact['artifact_id']} content does not match declared SHA-256"
            )
        versions.append(actual)
    return tuple(versions)
