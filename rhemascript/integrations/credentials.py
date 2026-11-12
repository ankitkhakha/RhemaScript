"""Owner-operated local YouTube credential file setup and loading.

POSIX-only: creates owner-only files and refuses unsafe paths. This is access-
controlled plaintext storage, not encryption or an operating-system keychain.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
from pathlib import Path
from typing import Sequence


class PrivateCredentialError(RuntimeError):
    """Safe, non-secret-bearing credential storage error."""


_KEYS = ("client_id", "refresh_token")
_MAX_BYTES = 16_384


def _check_private_parent(parent: Path) -> None:
    if os.name != "posix":
        raise PrivateCredentialError(
            "the built-in private credential file is supported only on POSIX; "
            "use an operating-system credential manager and the documented environment variables"
        )
    try:
        parent_info = parent.lstat()
        info = parent.stat()
    except OSError:
        raise PrivateCredentialError("credential parent directory must already exist") from None
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PrivateCredentialError("credential parent must be a real directory, not a symlink")
    if info.st_uid != os.getuid():
        raise PrivateCredentialError("credential parent directory must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PrivateCredentialError(
            "credential parent directory permissions must be owner-only (0700 or stricter)"
        )


def load_private_credentials(path: str | os.PathLike[str]) -> dict[str, str]:
    """Load a JSON credential file only when its path and permissions are safe."""
    if os.name != "posix":
        raise PrivateCredentialError(
            "private credential file loading is supported only on POSIX; "
            "use an operating-system credential manager and environment variables"
        )
    target = Path(path).expanduser()
    _check_private_parent(target.parent)
    try:
        info = target.lstat()
    except OSError:
        raise PrivateCredentialError("credential file is missing or inaccessible") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PrivateCredentialError("credential path must be a regular non-symlink file")
    if info.st_uid != os.getuid():
        raise PrivateCredentialError("credential file must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PrivateCredentialError("credential file permissions must be owner-only (0600 or stricter)")
    if info.st_size > _MAX_BYTES:
        raise PrivateCredentialError("credential file exceeds the supported size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode)
                    or opened.st_ino != info.st_ino
                    or opened.st_dev != info.st_dev
                    or opened.st_uid != os.getuid()
                    or stat.S_IMODE(opened.st_mode) & 0o077
                    or opened.st_size > _MAX_BYTES):
                raise PrivateCredentialError("credential file changed or became unsafe during validation")
            raw = os.read(fd, _MAX_BYTES + 1)
        finally:
            os.close(fd)
    except PrivateCredentialError:
        raise
    except OSError:
        raise PrivateCredentialError("credential file could not be opened safely") from None
    if len(raw) > _MAX_BYTES:
        raise PrivateCredentialError("credential file exceeds the supported size limit")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise PrivateCredentialError("credential file is not valid UTF-8 JSON") from None
    if not isinstance(data, dict) or set(data) not in (set(_KEYS), {"client_id", "client_secret", "refresh_token"}):
        raise PrivateCredentialError("credential file must contain exactly client_id and refresh_token")
    if any(not isinstance(data[key], str) or not data[key].strip() for key in _KEYS):
        raise PrivateCredentialError("credential file contains an empty or invalid credential field")
    return {key: data[key].strip() for key in _KEYS}


def write_private_credentials(path: str | os.PathLike[str], *,
                              client_id: str, refresh_token: str,
                              client_secret: str | None = None) -> None:
    """Create a new owner-only credential file; never overwrite an existing path."""
    target = Path(path).expanduser()
    _check_private_parent(target.parent)
    values = {
        "client_id": client_id.strip() if isinstance(client_id, str) else "",
        "refresh_token": refresh_token.strip() if isinstance(refresh_token, str) else "",
    }
    if any(not value for value in values.values()):
        raise PrivateCredentialError("client ID and refresh token are required")
    payload = (json.dumps(values, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
    except FileExistsError:
        raise PrivateCredentialError(
            "credential file already exists; refusing to overwrite it"
        ) from None
    except OSError:
        raise PrivateCredentialError("credential file could not be created safely") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a new owner-only local RhemaScript YouTube credential file"
    )
    parser.add_argument("--path", required=True,
                        help="new credential file path inside an existing private directory")
    args = parser.parse_args(argv)
    try:
        client_id = input("Google OAuth client ID: ").strip()
        refresh_token = getpass.getpass("Google OAuth refresh token (input hidden): ")
        write_private_credentials(
            args.path, client_id=client_id,
            refresh_token=refresh_token,
        )
    except (PrivateCredentialError, EOFError, KeyboardInterrupt):
        print("Credential setup stopped; no credential values were displayed.")
        return 2
    print("Owner-only credential file created. Values were not displayed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
