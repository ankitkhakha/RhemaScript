"""Safe, offline persistence for verified YouTube Analytics evidence objects."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any

from rhemascript.evidence.artifact_verification import verify_artifact
from .youtube_analytics_evidence import (
    YouTubeAnalyticsEvidenceError,
    verify_analytics_evidence_snapshot,
)
from .youtube_analytics_insights import (
    YouTubeAnalyticsInsightError,
    verify_analytics_period_comparison,
)


class YouTubeAnalyticsArtifactStoreError(ValueError):
    """Analytics evidence could not be safely persisted or verified."""


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise YouTubeAnalyticsArtifactStoreError(f"{field} must be a non-empty string")
    return value


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise YouTubeAnalyticsArtifactStoreError(
            "Analytics evidence must be canonical JSON"
        ) from None


def _open_parent(root: str | os.PathLike[str], relative_path: str) -> tuple[int, str, list[int]]:
    if not isinstance(relative_path, str) or not relative_path.strip() or "\\" in relative_path:
        raise YouTubeAnalyticsArtifactStoreError(
            "artifact path must be a canonical relative POSIX path"
        )
    rel = PurePosixPath(relative_path)
    if (rel.is_absolute() or not rel.parts
            or rel.as_posix() != relative_path
            or any(part in ("", ".", "..") for part in rel.parts)):
        raise YouTubeAnalyticsArtifactStoreError(
            "artifact path must be a canonical relative path beneath evidence root"
        )
    root_path = Path(root).expanduser()
    try:
        root_info = root_path.lstat()
    except OSError:
        raise YouTubeAnalyticsArtifactStoreError("evidence root is unavailable") from None
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise YouTubeAnalyticsArtifactStoreError("evidence root must be a real directory")
    if (os.open not in getattr(os, "supports_dir_fd", set())
            or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW")):
        raise YouTubeAnalyticsArtifactStoreError(
            "safe descriptor-relative file creation is unavailable on this platform"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    opened: list[int] = []
    try:
        root_fd = os.open(root_path.resolve(strict=True), flags)
        opened.append(root_fd)
        opened_info = os.fstat(root_fd)
        if (opened_info.st_dev, opened_info.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise YouTubeAnalyticsArtifactStoreError("evidence root changed during file creation")
        parent_fd = root_fd
        for component in rel.parts[:-1]:
            child_fd = os.open(component, flags, dir_fd=parent_fd)
            opened.append(child_fd)
            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                raise YouTubeAnalyticsArtifactStoreError("artifact parent is not a directory")
            parent_fd = child_fd
        return parent_fd, rel.parts[-1], opened
    except OSError:
        for fd in reversed(opened):
            os.close(fd)
        raise YouTubeAnalyticsArtifactStoreError(
            "artifact parent is unavailable or contains a symlink"
        ) from None
    except Exception:
        for fd in reversed(opened):
            os.close(fd)
        raise


def persist_analytics_evidence_artifact(
    payload: dict[str, Any],
    *,
    evidence_root: str | os.PathLike[str],
    relative_path: str,
    artifact_id: str,
    project_id: str,
    project_version: str,
    version: str = "1",
    current_snapshot_artifact_id: str | None = None,
    previous_snapshot_artifact_id: str | None = None,
) -> dict[str, Any]:
    """Persist verified evidence without overwriting; return a DRAFT pack record.

    Parent directories must already exist. No symlink is followed and an existing
    destination is never replaced. The internal digest and file-byte digest are
    separate values. DRAFT is retained even after byte verification; verification
    does not confer approval or provider authenticity.
    """
    artifact_id = _required_text(artifact_id, "artifact_id")
    project_id = _required_text(project_id, "project_id")
    project_version = _required_text(project_version, "project_version")
    version = _required_text(version, "version")
    if not isinstance(payload, dict):
        raise YouTubeAnalyticsArtifactStoreError("payload must be an object")

    artifact_type = payload.get("evidence_type")
    try:
        if artifact_type == "YOUTUBE_ANALYTICS_REPORT_SNAPSHOT":
            verify_analytics_evidence_snapshot(payload)
            artifact_kind = "YOUTUBE_ANALYTICS_SNAPSHOT"
            metadata: dict[str, Any] = {"snapshot_sha256": payload["snapshot_sha256"]}
        elif artifact_type == "YOUTUBE_ANALYTICS_PERIOD_COMPARISON":
            verify_analytics_period_comparison(payload)
            artifact_kind = "YOUTUBE_ANALYTICS_COMPARISON"
            current_snapshot_artifact_id = _required_text(
                current_snapshot_artifact_id, "current_snapshot_artifact_id"
            )
            previous_snapshot_artifact_id = _required_text(
                previous_snapshot_artifact_id, "previous_snapshot_artifact_id"
            )
            if current_snapshot_artifact_id == previous_snapshot_artifact_id:
                raise YouTubeAnalyticsArtifactStoreError(
                    "comparison must reference two distinct snapshot artifacts"
                )
            metadata = {
                "comparison_sha256": payload["comparison_sha256"],
                "current_snapshot_artifact_id": current_snapshot_artifact_id,
                "previous_snapshot_artifact_id": previous_snapshot_artifact_id,
                "current_snapshot_sha256": payload["current_snapshot_sha256"],
                "previous_snapshot_sha256": payload["previous_snapshot_sha256"],
            }
        else:
            raise YouTubeAnalyticsArtifactStoreError("unsupported Analytics evidence type")
    except (YouTubeAnalyticsEvidenceError, YouTubeAnalyticsInsightError) as exc:
        raise YouTubeAnalyticsArtifactStoreError(
            f"payload verification failed: {exc}"
        ) from None

    envelope = {
        "evidence_id": artifact_id,
        "evidence_version": version,
        "artifact_type": artifact_kind,
        "project_id": project_id,
        "project_version": project_version,
        "payload": payload,
    }
    content = _canonical_json(envelope)
    parent_fd, filename, opened = _open_parent(evidence_root, relative_path)
    file_fd: int | None = None
    created = False
    verified = None
    failure: Exception | None = None
    try:
        file_fd = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        created = True
        view = memoryview(content)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(file_fd)
        os.fsync(parent_fd)
        verified = verify_artifact(
            evidence_root, relative_path, evidence_id=artifact_id, version=version
        )
    except FileExistsError:
        failure = YouTubeAnalyticsArtifactStoreError(
            "refusing to overwrite an existing evidence artifact"
        )
    except Exception:
        failure = YouTubeAnalyticsArtifactStoreError(
            "evidence artifact could not be safely written and byte-verified"
        )
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if failure is not None and created:
            try:
                os.unlink(filename, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass
        for fd in reversed(opened):
            os.close(fd)

    if failure is not None:
        raise failure
    assert verified is not None
    return {
        "artifact_id": artifact_id,
        "project_id": project_id,
        "project_version": project_version,
        "artifact_type": artifact_kind,
        "version": version,
        "status": "DRAFT",
        "local_path": verified.relative_path,
        "sha256": verified.sha256,
        **metadata,
    }
