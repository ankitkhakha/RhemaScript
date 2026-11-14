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
import weakref


class EvidenceIntegrityError(ValueError):
    pass


_VERIFIED_EVIDENCE_TOKEN = object()
_VERIFIED_BINDING_TOKEN = object()
_VERIFIED_EVIDENCE_INSTANCES: dict[int, weakref.ReferenceType] = {}
_VERIFIED_BINDING_INSTANCES: dict[int, weakref.ReferenceType] = {}


def _register_instance(value: object, registry: dict[int, weakref.ReferenceType]) -> None:
    identity = id(value)

    def discard(reference: weakref.ReferenceType) -> None:
        if registry.get(identity) is reference:
            registry.pop(identity, None)

    registry[identity] = weakref.ref(value, discard)


def _is_registered_instance(value: object, registry: dict[int, weakref.ReferenceType]) -> bool:
    reference = registry.get(id(value))
    return reference is not None and reference() is value


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names at every depth."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON object contains a duplicate member name")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject JavaScript-style NaN/Infinity tokens, which are not standard JSON."""
    raise ValueError(f"JSON contains a non-standard numeric constant: {value}")


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


def verify_artifact(
    root: str | os.PathLike[str],
    relative_path: str,
    *,
    evidence_id: str,
    version: str,
    expected_root_identity: tuple[int, int] | None = None,
    expected_parent_identity: tuple[int, int] | None = None,
    expected_file_identity: tuple[int, int] | None = None,
) -> EvidenceVersion:
    """Hash one regular file beneath root and optionally bind its opened inode identities.

    Expected identities let a creator verify that path-based lookup reaches the exact
    root, parent directory and file descriptors it pinned while creating the artifact.
    The directory entries are checked again after hashing so a rename/replacement
    during verification fails closed.
    """
    if not all(isinstance(x, str) and x.strip() for x in (relative_path, evidence_id, version)):
        raise EvidenceIntegrityError("path, evidence_id and version must be non-empty strings")
    rel = PurePosixPath(relative_path)
    if rel.is_absolute() or not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
        raise EvidenceIntegrityError("artifact path must name a file beneath the evidence root")
    for identity in (expected_root_identity, expected_parent_identity, expected_file_identity):
        if identity is not None and (
            not isinstance(identity, tuple) or len(identity) != 2
            or any(not isinstance(part, int) or isinstance(part, bool) for part in identity)
        ):
            raise EvidenceIntegrityError("expected filesystem identity is invalid")

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

    if (os.open not in getattr(os, "supports_dir_fd", set())
            or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW")):
        raise EvidenceIntegrityError("safe descriptor-relative verification is unavailable on this platform")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    opened_directories: list[int] = []
    file_fd: int | None = None
    try:
        root_fd = os.open(root_real, directory_flags)
        opened_directories.append(root_fd)
        opened_root = os.fstat(root_fd)
        root_identity = (opened_root.st_dev, opened_root.st_ino)
        if root_identity != (root_info.st_dev, root_info.st_ino):
            raise EvidenceIntegrityError("evidence root changed during verification")
        if expected_root_identity is not None and root_identity != expected_root_identity:
            raise EvidenceIntegrityError("evidence root does not match the pinned creation directory")

        parent_fd = root_fd
        for component in rel.parts[:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            opened_directories.append(child_fd)
            parent_info = os.fstat(child_fd)
            if not stat.S_ISDIR(parent_info.st_mode):
                raise EvidenceIntegrityError("artifact parent must be a real directory")
            parent_fd = child_fd
        opened_parent = os.fstat(parent_fd)
        parent_identity = (opened_parent.st_dev, opened_parent.st_ino)
        if expected_parent_identity is not None and parent_identity != expected_parent_identity:
            raise EvidenceIntegrityError("artifact parent does not match the pinned creation directory")

        file_fd = os.open(rel.parts[-1], file_flags, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        file_identity = (opened.st_dev, opened.st_ino)
        if not stat.S_ISREG(opened.st_mode):
            raise EvidenceIntegrityError("artifact must be a regular file")
        if expected_file_identity is not None and file_identity != expected_file_identity:
            raise EvidenceIntegrityError("artifact file does not match the inode created by this operation")

        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after_read = os.fstat(file_fd)
        if (opened.st_dev, opened.st_ino, opened.st_size,
                opened.st_mtime_ns, opened.st_ctime_ns) != (
                after_read.st_dev, after_read.st_ino, after_read.st_size,
                after_read.st_mtime_ns, after_read.st_ctime_ns):
            raise EvidenceIntegrityError("artifact changed while being read")

        # Confirm that the named path still resolves to the exact descriptors
        # whose bytes were hashed. This catches root/parent/file replacement
        # while verification was in progress.
        current_root = root_path.lstat()
        if (stat.S_ISLNK(current_root.st_mode) or not stat.S_ISDIR(current_root.st_mode)
                or (current_root.st_dev, current_root.st_ino) != root_identity):
            raise EvidenceIntegrityError("evidence root changed during verification")
        for index, component in enumerate(rel.parts[:-1]):
            entry = os.stat(
                component, dir_fd=opened_directories[index], follow_symlinks=False
            )
            child = os.fstat(opened_directories[index + 1])
            if (not stat.S_ISDIR(entry.st_mode)
                    or (entry.st_dev, entry.st_ino) != (child.st_dev, child.st_ino)):
                raise EvidenceIntegrityError("artifact parent changed during verification")
        current_entry = os.stat(rel.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(current_entry.st_mode)
                or (current_entry.st_dev, current_entry.st_ino) != file_identity):
            raise EvidenceIntegrityError("artifact destination changed during verification")
    except EvidenceIntegrityError:
        raise
    except OSError as exc:
        raise EvidenceIntegrityError("artifact is missing or could not be safely read") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(opened_directories):
            os.close(descriptor)

    result = EvidenceVersion(
        evidence_id, rel.as_posix(), version, digest.hexdigest(), size,
        _VERIFIED_EVIDENCE_TOKEN,
    )
    _register_instance(result, _VERIFIED_EVIDENCE_INSTANCES)
    return result


def _read_artifact_bytes(root: str | os.PathLike[str], relative_path: str) -> tuple[str, bytes]:
    """Read one regular file beneath root using descriptor-relative no-follow traversal."""
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise EvidenceIntegrityError("artifact path must be a non-empty string")
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
    if (os.open not in getattr(os, "supports_dir_fd", set())
            or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW")):
        raise EvidenceIntegrityError("safe descriptor-relative verification is unavailable on this platform")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    directories: list[int] = []
    file_fd: int | None = None
    try:
        root_fd = os.open(root_real, directory_flags)
        directories.append(root_fd)
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise EvidenceIntegrityError("evidence root changed during verification")
        parent_fd = root_fd
        for component in rel.parts[:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            directories.append(child_fd)
            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                raise EvidenceIntegrityError("artifact parent must be a real directory")
            parent_fd = child_fd
        file_fd = os.open(rel.parts[-1], file_flags, dir_fd=parent_fd)
        file_before = os.fstat(file_fd)
        if not stat.S_ISREG(file_before.st_mode):
            raise EvidenceIntegrityError("artifact must be a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        file_after = os.fstat(file_fd)
        if (file_before.st_dev, file_before.st_ino, file_before.st_size,
                file_before.st_mtime_ns, file_before.st_ctime_ns) != (
                file_after.st_dev, file_after.st_ino, file_after.st_size,
                file_after.st_mtime_ns, file_after.st_ctime_ns):
            raise EvidenceIntegrityError("artifact changed while being read")

        current_root = root_path.lstat()
        root_identity = (opened_root.st_dev, opened_root.st_ino)
        if (stat.S_ISLNK(current_root.st_mode) or not stat.S_ISDIR(current_root.st_mode)
                or (current_root.st_dev, current_root.st_ino) != root_identity):
            raise EvidenceIntegrityError("evidence root changed during verification")
        for index, component in enumerate(rel.parts[:-1]):
            entry = os.stat(component, dir_fd=directories[index], follow_symlinks=False)
            child = os.fstat(directories[index + 1])
            if (not stat.S_ISDIR(entry.st_mode)
                    or (entry.st_dev, entry.st_ino) != (child.st_dev, child.st_ino)):
                raise EvidenceIntegrityError("artifact parent changed during verification")
        current_entry = os.stat(rel.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(current_entry.st_mode)
                or (current_entry.st_dev, current_entry.st_ino) != (
                    file_before.st_dev, file_before.st_ino
                )):
            raise EvidenceIntegrityError("artifact destination changed during verification")
        return rel.as_posix(), b"".join(chunks)
    except EvidenceIntegrityError:
        raise
    except OSError as exc:
        raise EvidenceIntegrityError("artifact is missing or could not be safely read") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(directories):
            os.close(descriptor)


def verify_json_artifact(
    root: str | os.PathLike[str], relative_path: str
) -> tuple[EvidenceVersion, bytes]:
    """Read, identify and hash one JSON evidence artifact from the same byte snapshot.

    The returned bytes are exactly those whose digest is bound into the issued
    EvidenceVersion. Callers must parse/use these bytes rather than reopening the path.
    """
    rel_path, content = _read_artifact_bytes(root, relative_path)
    try:
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EvidenceIntegrityError("evidence artifact must contain valid unambiguous UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise EvidenceIntegrityError("evidence artifact JSON must be an object")
    evidence_id = payload.get("evidence_id")
    version = payload.get("evidence_version")
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        raise EvidenceIntegrityError("artifact must contain a non-empty evidence_id")
    if not isinstance(version, str) or not version.strip():
        raise EvidenceIntegrityError("artifact must contain a non-empty evidence_version")
    result = EvidenceVersion(
        evidence_id, rel_path, version, hashlib.sha256(content).hexdigest(), len(content),
        _VERIFIED_EVIDENCE_TOKEN,
    )
    _register_instance(result, _VERIFIED_EVIDENCE_INSTANCES)
    return result, content

def is_verified_evidence_version(evidence: EvidenceVersion) -> bool:
    """Recognise only the exact live object issued by verify_artifact."""
    return (
        isinstance(evidence, EvidenceVersion)
        and evidence._verification_token is _VERIFIED_EVIDENCE_TOKEN
        and _is_registered_instance(evidence, _VERIFIED_EVIDENCE_INSTANCES)
    )


def bind_assessment(assessment_id: str, evidence: EvidenceVersion, score: int) -> AssessmentBinding:
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 4:
        raise EvidenceIntegrityError("score must be an integer from 0 through 4")
    if not is_verified_evidence_version(evidence):
        raise EvidenceIntegrityError("assessment requires evidence returned by verify_artifact")
    if (not isinstance(evidence.sha256, str)
            or len(evidence.sha256) != 64
            or any(char not in "0123456789abcdef" for char in evidence.sha256)):
        raise EvidenceIntegrityError("verified evidence has an invalid SHA-256 digest")
    if not isinstance(assessment_id, str) or not assessment_id.strip():
        raise EvidenceIntegrityError("assessment_id must be non-empty")
    result = AssessmentBinding(
        assessment_id, evidence.evidence_id, evidence.version, evidence.sha256, score,
        _VERIFIED_BINDING_TOKEN,
    )
    _register_instance(result, _VERIFIED_BINDING_INSTANCES)
    return result


def is_verified_assessment_binding(binding: AssessmentBinding) -> bool:
    """Recognise only bindings issued by bind_assessment in this process."""
    return (
        isinstance(binding, AssessmentBinding)
        and binding._verification_token is _VERIFIED_BINDING_TOKEN
        and _is_registered_instance(binding, _VERIFIED_BINDING_INSTANCES)
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
        and is_verified_evidence_version(current)
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
