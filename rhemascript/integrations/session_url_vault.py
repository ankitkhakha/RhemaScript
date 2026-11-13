from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SessionUrlVaultError(ValueError):
    """A publish-session URL could not be stored or recovered safely."""


class SQLiteEncryptedSessionUrlVault:
    """Owner-only SQLite vault for encrypted provider resumable-session URLs.

    The 256-bit AES-GCM key is injected by the caller and is never stored in this
    database. The database stores only a non-secret session reference, URL digest,
    nonce and authenticated ciphertext.
    """

    _REF = re.compile(r"^[0-9a-f]{64}$")
    _SHA256 = re.compile(r"^[0-9a-f]{64}$")
    _ALLOWED_HOSTS = {"www.googleapis.com", "youtube.googleapis.com"}
    _MAX_URL_BYTES = 8192

    def __init__(self, path: str | os.PathLike[str], key: bytes):
        if not isinstance(key, bytes) or len(key) != 32:
            raise SessionUrlVaultError("session URL vault key must be exactly 32 bytes")
        self.path = Path(path).expanduser()
        self._cipher = AESGCM(bytes(key))
        self._prepare_database()

    @classmethod
    def from_environment(
        cls,
        path: str | os.PathLike[str],
        *,
        variable: str = "RHEMASCRIPT_SESSION_URL_VAULT_KEY",
        environ: dict[str, str] | None = None,
    ) -> "SQLiteEncryptedSessionUrlVault":
        values = os.environ if environ is None else environ
        raw = values.get(variable)
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
            raise SessionUrlVaultError(
                f"{variable} must contain a 64-character hexadecimal key; no key was read from disk"
            )
        return cls(path, bytes.fromhex(raw))

    def __repr__(self) -> str:
        return f"{type(self).__name__}(path={str(self.path)!r}, key=<redacted>)"

    @classmethod
    def _validate_reference(cls, session_ref: str) -> None:
        if not isinstance(session_ref, str) or not cls._REF.fullmatch(session_ref):
            raise SessionUrlVaultError("session reference must be a lowercase SHA-256 digest")

    @classmethod
    def _validate_url(cls, url: str) -> bytes:
        if not isinstance(url, str) or not url or len(url.encode("utf-8")) > cls._MAX_URL_BYTES:
            raise SessionUrlVaultError("provider session URL is invalid or exceeds the size limit")
        try:
            parsed = urlparse(url)
            port = parsed.port
        except ValueError:
            raise SessionUrlVaultError("provider session URL is malformed") from None
        if (
            parsed.scheme.lower() != "https"
            or parsed.hostname not in cls._ALLOWED_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or parsed.fragment
            or not (parsed.path == "/upload/youtube/v3/videos" or parsed.path.startswith("/upload/youtube/v3/videos/"))
        ):
            raise SessionUrlVaultError("provider session URL is outside the YouTube upload allowlist")
        return url.encode("utf-8")

    def _prepare_database(self) -> None:
        parent = self.path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            parent_stat = parent.lstat()
        except OSError:
            raise SessionUrlVaultError("session URL vault directory is unavailable") from None
        if (
            stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or parent_stat.st_mode & 0o077
        ):
            raise SessionUrlVaultError("session URL vault directory must be owner-only and non-symlinked")
        try:
            file_stat = self.path.lstat()
        except FileNotFoundError:
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(self.path, flags, 0o600)
                os.close(fd)
            except OSError:
                raise SessionUrlVaultError("session URL vault database could not be created safely") from None
        except OSError:
            raise SessionUrlVaultError("session URL vault database is unavailable") from None
        else:
            if (
                stat.S_ISLNK(file_stat.st_mode)
                or not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.getuid()
                or file_stat.st_mode & 0o077
            ):
                raise SessionUrlVaultError("session URL vault database must be owner-only and non-symlinked")
            os.chmod(self.path, 0o600)
        db = self._connect()
        try:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA secure_delete=ON")
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS session_urls (
                    session_ref TEXT PRIMARY KEY,
                    url_sha256 TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
        except sqlite3.Error:
            raise SessionUrlVaultError("session URL vault schema could not be initialized") from None
        finally:
            db.close()
        os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        try:
            current = self.path.lstat()
        except OSError:
            raise SessionUrlVaultError("session URL vault database is unavailable") from None
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise SessionUrlVaultError("session URL vault database path is unsafe")
        db = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA busy_timeout=5000")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA secure_delete=ON")
        except sqlite3.Error:
            db.close()
            raise SessionUrlVaultError("session URL vault database settings could not be applied") from None
        return db

    def store(self, session_ref: str, url: str) -> str:
        self._validate_reference(session_ref)
        raw = self._validate_url(url)
        digest = hashlib.sha256(raw).hexdigest()
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, raw, session_ref.encode("ascii"))
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO session_urls(session_ref,url_sha256,nonce,ciphertext,created_at) VALUES(?,?,?,?,?)",
                (session_ref, digest, nonce, ciphertext, datetime.now(timezone.utc).isoformat()),
            )
            db.execute("COMMIT")
            os.chmod(self.path, 0o600)
            return digest
        except sqlite3.IntegrityError:
            db.execute("ROLLBACK")
            raise SessionUrlVaultError("session URL already exists for this reference; overwrite is forbidden") from None
        except sqlite3.Error:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise SessionUrlVaultError("session URL could not be stored durably") from None
        finally:
            db.close()

    def retrieve(self, session_ref: str, *, expected_sha256: str) -> str:
        self._validate_reference(session_ref)
        if not isinstance(expected_sha256, str) or not self._SHA256.fullmatch(expected_sha256):
            raise SessionUrlVaultError("expected session URL digest is invalid")
        db = self._connect()
        try:
            row = db.execute(
                "SELECT url_sha256,nonce,ciphertext FROM session_urls WHERE session_ref=?",
                (session_ref,),
            ).fetchone()
        except sqlite3.Error:
            raise SessionUrlVaultError("session URL vault record could not be read") from None
        finally:
            db.close()
        if row is None:
            raise SessionUrlVaultError("session URL is not present in the encrypted vault")
        if not hmac_compare(row["url_sha256"], expected_sha256):
            raise SessionUrlVaultError("session URL vault digest does not match the publish-session registry")
        try:
            raw = self._cipher.decrypt(bytes(row["nonce"]), bytes(row["ciphertext"]), session_ref.encode("ascii"))
        except (InvalidTag, ValueError):
            raise SessionUrlVaultError("session URL vault authentication failed") from None
        if not hmac_compare(hashlib.sha256(raw).hexdigest(), expected_sha256):
            raise SessionUrlVaultError("decrypted session URL digest does not match the registry")
        try:
            url = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise SessionUrlVaultError("decrypted session URL is not valid UTF-8") from None
        self._validate_url(url)
        return url

    def delete(self, session_ref: str, *, expected_sha256: str) -> bool:
        self._validate_reference(session_ref)
        if not isinstance(expected_sha256, str) or not self._SHA256.fullmatch(expected_sha256):
            raise SessionUrlVaultError("expected session URL digest is invalid")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT url_sha256 FROM session_urls WHERE session_ref=?",
                (session_ref,),
            ).fetchone()
            if row is None:
                db.execute("COMMIT")
                return False
            if not hmac_compare(row["url_sha256"], expected_sha256):
                db.execute("ROLLBACK")
                raise SessionUrlVaultError("session URL digest mismatch; deletion denied")
            db.execute("DELETE FROM session_urls WHERE session_ref=?", (session_ref,))
            db.execute("COMMIT")
            os.chmod(self.path, 0o600)
            return True
        except sqlite3.Error:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise SessionUrlVaultError("session URL could not be deleted safely") from None
        finally:
            db.close()

    def verify_all(self) -> int:
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT session_ref,url_sha256,nonce,ciphertext FROM session_urls ORDER BY session_ref"
            ).fetchall()
        except sqlite3.Error:
            raise SessionUrlVaultError("session URL vault integrity scan failed") from None
        finally:
            db.close()
        for row in rows:
            self.retrieve(row["session_ref"], expected_sha256=row["url_sha256"])
        return len(rows)

    def backup_to(self, destination: str | os.PathLike[str]) -> Path:
        target = Path(destination).expanduser()
        if target.resolve() == self.path.resolve():
            raise SessionUrlVaultError("session URL vault backup destination must differ from source")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_stat = target.parent.lstat()
        if (
            stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or parent_stat.st_mode & 0o077
        ):
            raise SessionUrlVaultError("session URL vault backup directory must be owner-only")
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(target, flags, 0o600)
            os.close(fd)
        except OSError:
            raise SessionUrlVaultError("session URL vault backup target is not safely creatable") from None
        source = self._connect()
        backup = sqlite3.connect(str(target), timeout=5.0)
        try:
            source.backup(backup)
            backup.commit()
        except sqlite3.Error:
            raise SessionUrlVaultError("session URL vault backup failed") from None
        finally:
            backup.close()
            source.close()
        os.chmod(target, 0o600)
        return target


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def publish_session_vault_reference(identity: dict[str, object]) -> str:
    """Return a deterministic non-secret reference for one exact publish session."""
    required = (
        "project_id", "project_version", "request_id", "approval_fingerprint",
        "artifact_id", "artifact_version", "artifact_sha256", "artifact_size_bytes",
    )
    if not isinstance(identity, dict) or set(identity) != set(required):
        raise SessionUrlVaultError("publish-session identity has an invalid shape")
    payload = {key: identity[key] for key in required}
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
