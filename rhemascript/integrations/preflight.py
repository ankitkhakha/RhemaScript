"""Offline-only preflight for local YouTube integration configuration.

This module never performs OAuth, network requests, file creation, or publishing.
It reports credential presence only; secret values are never displayed.
"""
from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path
from typing import Sequence

from rhemascript.integrations.audit import AuditSinkError, JsonlAuditSink
from rhemascript.integrations.credentials import PrivateCredentialError, load_private_credentials


CREDENTIAL_ENV = (
    "RHEMASCRIPT_YOUTUBE_CLIENT_ID",
    "RHEMASCRIPT_YOUTUBE_REFRESH_TOKEN",
)


def inspect_local_preflight(audit_log: str | os.PathLike[str],
                            environ: dict[str, str] | None = None,
                            credential_file: str | os.PathLike[str] | None = None) -> list[tuple[str, bool, str]]:
    """Return safe status checks without displaying secrets or touching the network."""
    env = os.environ if environ is None else environ
    checks: list[tuple[str, bool, str]] = []
    if credential_file is not None:
        try:
            load_private_credentials(credential_file)
            checks.append(("OAuth private credential file", True,
                           "file and owner-only permissions verified; values not displayed"))
        except (PrivateCredentialError, OSError, ValueError) as exc:
            checks.append(("OAuth private credential file", False, str(exc)))
    else:
        present = [bool(env.get(name, "").strip()) for name in CREDENTIAL_ENV]
        checks.append((
            "OAuth environment variables",
            all(present),
            "all three values are present (values not displayed)" if all(present)
            else f"{sum(present)}/3 values present; missing values must be configured locally",
        ))

    try:
        sink = JsonlAuditSink(audit_log)
        path = sink.path
        parent = path.parent
        if path.is_symlink():
            raise AuditSinkError("audit destination is a symlink")
        if not parent.is_dir():
            raise AuditSinkError("audit parent is not a directory")
        if os.name == "posix":
            parent_mode = stat.S_IMODE(parent.stat().st_mode)
            if parent_mode & 0o022:
                raise AuditSinkError("audit parent directory is group/world writable")
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise AuditSinkError("audit destination is not a regular file")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
                raise AuditSinkError("existing audit file permissions are broader than 0600")
        checks.append(("Local audit destination", True,
                       "existing controlled directory; file absent or regular and owner-only"))
    except (AuditSinkError, OSError, ValueError) as exc:
        checks.append(("Local audit destination", False, str(exc)))

    checks.append(("Network and OAuth actions", True,
                   "not attempted; this preflight is offline and read-only"))
    checks.append(("Publishing and external writes", True,
                   "not attempted; no authority is granted by this preflight"))
    return checks


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline-only RhemaScript YouTube configuration preflight"
    )
    parser.add_argument("--audit-log", required=True,
                        help="path to the local JSONL audit file in an existing private directory")
    parser.add_argument("--credential-file",
                        help="optional owner-only local OAuth credential file; otherwise check environment variables")
    args = parser.parse_args(argv)
    checks = inspect_local_preflight(args.audit_log, credential_file=args.credential_file)
    print("RhemaScript YouTube preflight (offline; no secrets displayed)")
    for label, passed, detail in checks:
        print(f"[{'PASS' if passed else 'CHECK'}] {label}: {detail}")
    return 0 if all(passed for _, passed, _ in checks) else 2


if __name__ == "__main__":
    raise SystemExit(main())
