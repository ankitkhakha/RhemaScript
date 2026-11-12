"""Minimal HMAC-signed bearer-token verification exercise.

This is a learning implementation, not a replacement for a maintained OIDC/JWT
library or a production identity provider. Keys are injected by the caller.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Callable

from raei.api_contracts import Principal


class TokenError(ValueError):
    pass


_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


def _decode_segment(segment: str) -> bytes:
    if not segment or not _B64URL.fullmatch(segment):
        raise TokenError("malformed token encoding")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except Exception as exc:
        raise TokenError("malformed token encoding") from exc


def _json_no_duplicates(raw: bytes) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise TokenError("duplicate JSON claim")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except TokenError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenError("invalid token JSON") from exc
    if not isinstance(value, dict):
        raise TokenError("token segment must be a JSON object")
    return value


def _encode_segment(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def issue_lab_token(subject: str, roles: list[str], secret: bytes, issuer: str,
                    audience: str, expires_at: int, not_before: int | None = None) -> str:
    """Create deterministic test tokens; production issuance belongs to an IdP."""
    if len(secret) < 32:
        raise TokenError("HMAC secret must be at least 32 bytes")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": subject, "roles": roles, "iss": issuer, "aud": audience,
               "exp": expires_at}
    if not_before is not None:
        payload["nbf"] = not_before
    head = _encode_segment(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    body = _encode_segment(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{head}.{body}".encode("ascii")
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{head}.{body}.{_encode_segment(signature)}"


def verify_bearer_token(token: str, secret: bytes, issuer: str, audience: str,
                        allowed_roles: set[str],
                        clock: Callable[[], float] = time.time,
                        leeway_seconds: int = 0) -> Principal:
    if not isinstance(token, str) or len(token) > 8192:
        raise TokenError("invalid token size")
    if len(secret) < 32:
        raise TokenError("HMAC secret must be at least 32 bytes")
    if leeway_seconds < 0 or leeway_seconds > 60:
        raise TokenError("leeway must be between 0 and 60 seconds")
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("token must have three segments")
    header = _json_no_duplicates(_decode_segment(parts[0]))
    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise TokenError("unsupported token algorithm or type")
    signature = _decode_segment(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise TokenError("invalid token signature")
    claims = _json_no_duplicates(_decode_segment(parts[1]))
    subject, roles = claims.get("sub"), claims.get("roles")
    now = int(clock())
    exp, nbf = claims.get("exp"), claims.get("nbf", 0)
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 256:
        raise TokenError("invalid subject claim")
    if not isinstance(roles, list) or not roles or any(
        not isinstance(role, str) or role not in allowed_roles for role in roles
    ):
        raise TokenError("invalid or unrecognised roles")
    if len(roles) != len(set(roles)):
        raise TokenError("duplicate roles")
    if claims.get("iss") != issuer:
        raise TokenError("invalid issuer")
    aud = claims.get("aud")
    if aud != audience and not (isinstance(aud, list) and audience in aud):
        raise TokenError("invalid audience")
    if not isinstance(exp, int) or isinstance(exp, bool) or exp <= now - leeway_seconds:
        raise TokenError("token expired or invalid expiry")
    if not isinstance(nbf, int) or isinstance(nbf, bool) or nbf > now + leeway_seconds:
        raise TokenError("token not yet valid or invalid not-before")
    return Principal(subject=subject, roles=frozenset(roles), authenticated=True)
