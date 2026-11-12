"""Local evidence artefact verification and tamper-evident assessment binding.

The verifier is deliberately offline and dependency-free. HMAC checkpoints are
shared-secret authenticity anchors, not public-key signatures or immutable storage.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any


class EvidenceIntegrityError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class EvidenceVersion:
    evidence_id: str
    relative_path: str
    version: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class AssessmentBinding:
    assessment_id: str
    evidence_id: str
    evidence_version: str
    evidence_sha256: str
    score: int


def verify_artifact(root: str | os.PathLike[str], relative_path: str, *,
                    evidence_id: str, version: str) -> EvidenceVersion:
    """Hash one regular file strictly beneath root; reject traversal and symlinks."""
    if not all(isinstance(x, str) and x.strip() for x in (relative_path, evidence_id, version)):
        raise EvidenceIntegrityError("path, evidence_id and version must be non-empty strings")
    rel = PurePosixPath(relative_path)
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        raise EvidenceIntegrityError("artifact path must be a clean relative path beneath evidence root")
    root_path = Path(root).expanduser()
    try:
        root_info = root_path.lstat()
    except OSError as exc:
        raise EvidenceIntegrityError("evidence root is unavailable") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise EvidenceIntegrityError("evidence root must be a real directory, not a symlink")
    root_real = root_path.resolve(strict=True)
    candidate = root_real
    try:
        for part in rel.parts:
            candidate = candidate / part
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise EvidenceIntegrityError("symlink components are not permitted")
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceIntegrityError("artifact must be a regular file")
        if not candidate.resolve(strict=True).is_relative_to(root_real):
            raise EvidenceIntegrityError("artifact resolves outside evidence root")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(candidate, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise EvidenceIntegrityError("artifact changed during verification")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        finally:
            os.close(fd)
    except EvidenceIntegrityError:
        raise
    except OSError as exc:
        raise EvidenceIntegrityError("artifact is missing or could not be safely read") from exc
    return EvidenceVersion(evidence_id, rel.as_posix(), version, digest.hexdigest(), size)


def bind_assessment(assessment_id: str, evidence: EvidenceVersion, score: int) -> AssessmentBinding:
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 4:
        raise EvidenceIntegrityError("score must be an integer from 0 through 4")
    if not isinstance(evidence, EvidenceVersion):
        raise EvidenceIntegrityError("assessment requires a verified EvidenceVersion")
    if not isinstance(assessment_id, str) or not assessment_id.strip():
        raise EvidenceIntegrityError("assessment_id must be non-empty")
    return AssessmentBinding(assessment_id, evidence.evidence_id, evidence.version, evidence.sha256, score)


def verify_assessment_binding(binding: AssessmentBinding, current: EvidenceVersion) -> bool:
    """Return true only for exact evidence identity, version and content digest."""
    return (isinstance(binding, AssessmentBinding)
            and isinstance(current, EvidenceVersion)
            and binding.evidence_id == current.evidence_id
            and binding.evidence_version == current.version
            and hmac.compare_digest(binding.evidence_sha256, current.sha256))


class IntegrityLedger:
    """Append-only-in-process hash chain with externally retainable HMAC checkpoints."""
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(event) for event in self._events)

    def append(self, event: dict[str, Any]) -> str:
        if not isinstance(event, dict):
            raise EvidenceIntegrityError("ledger event must be an object")
        previous = self._events[-1]["event_hash"] if self._events else "0" * 64
        body = {"sequence": len(self._events) + 1, "previous_hash": previous, "payload": event}
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        self._events.append({**body, "event_hash": digest})
        return digest

    def verify(self) -> bool:
        previous = "0" * 64
        for index, event in enumerate(self._events, 1):
            if event.get("sequence") != index or event.get("previous_hash") != previous:
                return False
            body = {key: event[key] for key in ("sequence", "previous_hash", "payload")}
            digest = hashlib.sha256(_canonical(body)).hexdigest()
            if not hmac.compare_digest(str(event.get("event_hash", "")), digest):
                return False
            previous = digest
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
