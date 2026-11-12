"""Local evidence artefact verification and tamper-evident assessment binding.

The verifier is deliberately offline and dependency-free. HMAC checkpoints are
shared-secret authenticity anchors, not public-key signatures or immutable storage.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any


class EvidenceIntegrityError(ValueError):
    pass


_VERIFIED_EVIDENCE_TOKEN = object()
_VERIFIED_BINDING_TOKEN = object()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


@dataclass(frozen=True)
class EvidenceVersion:
    evidence_id: str
    relative_path: str
    version: str
    sha256: str
    size_bytes: int
    _verification_token: object = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class AssessmentBinding:
    assessment_id: str
    evidence_id: str
    evidence_version: str
    evidence_sha256: str
    score: int
    _verification_token: object = field(default=None, repr=False, compare=False)


def verify_artifact(root: str | os.PathLike[str], relative_path: str, *,
                    evidence_id: str, version: str) -> EvidenceVersion:
    """Hash one regular file beneath root without following any path-component symlink."""
    if not all(isinstance(x, str) and x.strip() for x in (relative_path, evidence_id, version)):
        raise EvidenceIntegrityError("path, evidence_id and version must be non-empty strings")
    rel = PurePosixPath(relative_path)
    if rel.is_absolute() or not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
        raise EvidenceIntegrityError("artifact path must name a file beneath the evidence root")

    root_path = Path(root).expanduser()
    try:
        root_info = root_path.lstat()
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise EvidenceIntegrityError("evidence root must be a real directory, not a symlink")
        root_real = root_path.resolve(strict=True)
    except EvidenceIntegrityError:
        raise
    except OSError as exc:
        raise EvidenceIntegrityError("evidence root is unavailable") from exc

    # Descriptor-relative traversal closes the lstat/open race on parent components.
    # On platforms without these primitives, fail closed instead of reverting to
    # path-based checks that can be raced by replacing a directory with a symlink.
    if os.open not in getattr(os, "supports_dir_fd", set()) or not hasattr(os, "O_DIRECTORY"):
        raise EvidenceIntegrityError("safe descriptor-relative verification is unavailable on this platform")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    opened_directories: list[int] = []
    file_fd: int | None = None
    try:
        root_fd = os.open(root_real, directory_flags)
        opened_directories.append(root_fd)
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise EvidenceIntegrityError("evidence root changed during verification")

        parent_fd = root_fd
        for component in rel.parts[:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            opened_directories.append(child_fd)
            parent_info = os.fstat(child_fd)
            if not stat.S_ISDIR(parent_info.st_mode):
                raise EvidenceIntegrityError("artifact parent must be a real directory")
            parent_fd = child_fd

        file_fd = os.open(rel.parts[-1], file_flags, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode):
            raise EvidenceIntegrityError("artifact must be a regular file")

        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    except EvidenceIntegrityError:
        raise
    except OSError as exc:
        raise EvidenceIntegrityError("artifact is missing or could not be safely read") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(opened_directories):
            os.close(descriptor)

    return EvidenceVersion(
        evidence_id, rel.as_posix(), version, digest.hexdigest(), size,
        _VERIFIED_EVIDENCE_TOKEN,
    )


def bind_assessment(assessment_id: str, evidence: EvidenceVersion, score: int) -> AssessmentBinding:
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 4:
        raise EvidenceIntegrityError("score must be an integer from 0 through 4")
    if (not isinstance(evidence, EvidenceVersion)
            or evidence._verification_token is not _VERIFIED_EVIDENCE_TOKEN):
        raise EvidenceIntegrityError("assessment requires evidence returned by verify_artifact")
    if (not isinstance(evidence.sha256, str)
            or len(evidence.sha256) != 64
            or any(char not in "0123456789abcdef" for char in evidence.sha256)):
        raise EvidenceIntegrityError("verified evidence has an invalid SHA-256 digest")
    if not isinstance(assessment_id, str) or not assessment_id.strip():
        raise EvidenceIntegrityError("assessment_id must be non-empty")
    return AssessmentBinding(
        assessment_id, evidence.evidence_id, evidence.version, evidence.sha256, score,
        _VERIFIED_BINDING_TOKEN,
    )


def is_verified_assessment_binding(binding: AssessmentBinding) -> bool:
    """Recognise only bindings issued by bind_assessment in this process."""
    return (
        isinstance(binding, AssessmentBinding)
        and binding._verification_token is _VERIFIED_BINDING_TOKEN
        and isinstance(binding.assessment_id, str) and bool(binding.assessment_id.strip())
        and isinstance(binding.evidence_id, str) and bool(binding.evidence_id.strip())
        and isinstance(binding.evidence_version, str) and bool(binding.evidence_version.strip())
        and isinstance(binding.evidence_sha256, str)
        and len(binding.evidence_sha256) == 64
        and all(char in "0123456789abcdef" for char in binding.evidence_sha256)
        and isinstance(binding.score, int) and not isinstance(binding.score, bool)
        and 0 <= binding.score <= 4
    )


def verify_assessment_binding(binding: AssessmentBinding, current: EvidenceVersion) -> bool:
    """Return true only for an authentic binding and exact verified evidence identity."""
    return (
        is_verified_assessment_binding(binding)
        and isinstance(current, EvidenceVersion)
        and current._verification_token is _VERIFIED_EVIDENCE_TOKEN
        and binding.evidence_id == current.evidence_id
        and binding.evidence_version == current.version
        and hmac.compare_digest(binding.evidence_sha256, current.sha256)
    )


class IntegrityLedger:
    """Append-only-in-process hash chain with externally retainable HMAC checkpoints."""
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        # Return detached JSON snapshots, including nested payload values.
        return tuple(json.loads(_canonical(event).decode("utf-8")) for event in self._events)

    def append(self, event: dict[str, Any]) -> str:
        if not isinstance(event, dict):
            raise EvidenceIntegrityError("ledger event must be an object")
        try:
            payload = json.loads(_canonical(event).decode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise EvidenceIntegrityError("ledger event must contain canonical JSON values") from exc
        previous = self._events[-1]["event_hash"] if self._events else "0" * 64
        body = {"sequence": len(self._events) + 1, "previous_hash": previous, "payload": payload}
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        self._events.append({**body, "event_hash": digest})
        return digest

    def verify(self) -> bool:
        previous = "0" * 64
        try:
            for index, event in enumerate(self._events, 1):
                if not isinstance(event, dict):
                    return False
                if event.get("sequence") != index or event.get("previous_hash") != previous:
                    return False
                body = {key: event[key] for key in ("sequence", "previous_hash", "payload")}
                digest = hashlib.sha256(_canonical(body)).hexdigest()
                if not hmac.compare_digest(str(event.get("event_hash", "")), digest):
                    return False
                previous = digest
        except (KeyError, TypeError, ValueError):
            return False
        return True

    def checkpoint(self, key: bytes) -> dict[str, Any]:
        if not isinstance(key, bytes) or len(key) < 32:
            raise EvidenceIntegrityError("checkpoint key must contain at least 32 bytes")
        if not self.verify():
            raise EvidenceIntegrityError("cannot checkpoint an invalid ledger")
        body = {"sequence": len(self._events),
                "head_hash": self._events[-1]["event_hash"] if self._events else "0" * 64}
        signature = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
        return {**body, "algorithm": "HMAC-SHA256", "signature": signature}

    def verify_checkpoint(self, checkpoint: dict[str, Any], key: bytes) -> bool:
        if not isinstance(checkpoint, dict) or not isinstance(key, bytes) or len(key) < 32:
            return False
        if not self.verify():
            return False
        body = {"sequence": len(self._events),
                "head_hash": self._events[-1]["event_hash"] if self._events else "0" * 64}
        if checkpoint.get("algorithm") != "HMAC-SHA256" or checkpoint.get("sequence") != body["sequence"]:
            return False
        if checkpoint.get("head_hash") != body["head_hash"]:
            return False
        expected = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
        return hmac.compare_digest(str(checkpoint.get("signature", "")), expected)
