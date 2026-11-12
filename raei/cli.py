"""Operator CLI for evidence-backed RAEI training and knowledge workflows."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from rhemascript.evidence.artifact_verification import verify_artifact
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry
from .curriculum import registry_summary
from .knowledge import RAEIKnowledgeError, record_knowledge, search_knowledge
from .training import (
    RAEITrainingError,
    build_training_brief,
    get_progress,
    next_unit,
    record_attempt,
)


class RAEICLIError(ValueError):
    """Safe operator-facing CLI error."""


def _database(path_value: str, *, create: bool = False) -> ReadinessRunRegistry:
    path = Path(path_value).expanduser()
    if not path.name or path.name in {".", ".."}:
        raise RAEICLIError("database path must name a file")
    parent = path.parent.absolute()
    current = Path(parent.anchor)
    try:
        for component in parent.parts[1:]:
            current = current / component
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RAEICLIError("database parent path must contain only real directories")
        if os.name == "posix":
            parent_info = parent.stat()
            if parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o077:
                raise RAEICLIError("database parent directory must be owner-controlled and private (0700)")
        if path.is_symlink():
            raise RAEICLIError("database must not be a symlink")
        if create:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
            os.fchmod(fd, 0o600)
            os.close(fd)
        elif not path.is_file():
            raise RAEICLIError("database does not exist; run 'python -m raei init' first")
        elif os.name == "posix":
            info = path.stat()
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise RAEICLIError("database file must be owner-controlled and private (0600)")
    except RAEICLIError:
        raise
    except FileExistsError as exc:
        raise RAEICLIError("database already exists") from exc
    except OSError as exc:
        raise RAEICLIError("database path is unavailable or unsafe") from exc
    return ReadinessRunRegistry(path)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m raei", description="Evidence-backed RAEI learning controls")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a private local learning registry")
    init.add_argument("--database", required=True)

    for name, help_text in (
        ("status", "show curriculum and recorded competency status"),
        ("next", "show the next eligible learning unit"),
        ("verify", "verify the local learning registry"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--database", required=True)
        cmd.add_argument("--evidence-root", required=True)

    brief = sub.add_parser("brief", help="build a training brief for one eligible unit")
    brief.add_argument("--database", required=True)
    brief.add_argument("--unit-id", required=True)
    brief.add_argument("--evidence-root", required=True)

    search = sub.add_parser("knowledge-search", help="search knowledge items; pending items are excluded by default")
    search.add_argument("--database", required=True)
    search.add_argument("--query", required=True)
    search.add_argument("--include-pending", action="store_true")
    search.add_argument("--evidence-root", required=True)

    for name, help_text in (
        ("record-attempt", "record an evidence-bound RAEI self-assessment"),
        ("record-knowledge", "record a knowledge artifact as pending human review"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--database", required=True)
        cmd.add_argument("--evidence-root", required=True)
        cmd.add_argument("--artifact-path", required=True, help="canonical JSON file relative to evidence root")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            registry = _database(args.database, create=True)
            print(_json({"status": "INITIALIZED", "database": str(Path(args.database).expanduser())}))
            return 0

        registry = _database(args.database)
        if not registry.verify_artifacts(args.evidence_root):
            raise RAEICLIError("registry or retained evidence artefact integrity verification failed")
        if args.command == "verify":
            valid = registry.verify_artifacts(args.evidence_root)
            print(_json({"integrity": "PASS" if valid else "FAIL"}))
            return 0 if valid else 2

        if args.command == "status":
            progress = get_progress(registry)
            counts: dict[str, int] = {}
            for item in progress.values():
                status = item.get("status", "NOT_STARTED")
                counts[status] = counts.get(status, 0) + 1
            print(_json({
                "curriculum": registry_summary(),
                "recorded_units": len(progress),
                "status_counts": counts,
                "registry_integrity": "PASS" if registry.verify() else "FAIL",
            }))
            return 0

        if args.command == "next":
            print(_json(next_unit(registry)))
            return 0

        if args.command == "brief":
            print(_json(build_training_brief(args.unit_id, registry)))
            return 0

        if args.command == "knowledge-search":
            print(_json(search_knowledge(registry, args.query, include_pending=args.include_pending)))
            return 0

        root = Path(args.evidence_root).expanduser()
        artifact = verify_artifact(
            root, args.artifact_path,
            evidence_id=_read_identity(root, args.artifact_path, "evidence_id"),
            version=_read_identity(root, args.artifact_path, "evidence_version"),
        )
        payload = json.loads((root / args.artifact_path).read_bytes())
        if args.command == "record-attempt":
            result = record_attempt(registry, payload, artifact)
        elif args.command == "record-knowledge":
            result = record_knowledge(registry, payload, artifact)
        else:
            raise RAEICLIError("unsupported command")
        print(_json(result))
        return 0
    except (RAEICLIError, RAEITrainingError, RAEIKnowledgeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"RAEI: {exc}", file=sys.stderr)
        return 2


def _read_identity(root: Path, relative_path: str, field: str) -> str:
    try:
        value = json.loads((root / relative_path).read_bytes())[field]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RAEICLIError(f"artifact must contain a valid {field}") from exc
    if not isinstance(value, str) or not value.strip():
        raise RAEICLIError(f"artifact must contain a non-empty {field}")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
