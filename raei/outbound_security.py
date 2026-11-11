"""Fail-closed outbound URL and upstream JSON validation exercises.

This module validates policy before a caller makes a request. It does not perform
network I/O, DNS pinning, redirect handling, or connection-time peer verification.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class OutboundRequestError(ValueError):
    pass


@dataclass(frozen=True)
class OutboundTarget:
    url: str
    hostname: str


def validate_outbound_url(url: str, allowed_hosts: set[str]) -> OutboundTarget:
    if not isinstance(url, str) or len(url) > 2048:
        raise OutboundRequestError("invalid URL length")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise OutboundRequestError("malformed URL") from exc
    if parsed.scheme.lower() != "https":
        raise OutboundRequestError("HTTPS is required")
    if not host or parsed.username is not None or parsed.password is not None:
        raise OutboundRequestError("hostname required; URL credentials forbidden")
    if parsed.fragment:
        raise OutboundRequestError("URL fragments are not allowed")
    if port not in (None, 443):
        raise OutboundRequestError("only HTTPS port 443 is allowed")
    host = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise OutboundRequestError("IP-literal destinations are forbidden")
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise OutboundRequestError("local destinations are forbidden")
    allowed = {item.rstrip(".").lower() for item in allowed_hosts}
    if not allowed or host not in allowed:
        raise OutboundRequestError("destination host is not allowlisted")
    normalized = urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))
    return OutboundTarget(normalized, host)


def validate_upstream_json(body: bytes, content_type: str, max_bytes: int = 65536):
    if not isinstance(body, bytes) or len(body) > max_bytes:
        raise OutboundRequestError("upstream body missing or exceeds size limit")
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise OutboundRequestError("upstream content type must be application/json")

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise OutboundRequestError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=no_duplicates)
    except OutboundRequestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OutboundRequestError("invalid upstream JSON") from exc
    if not isinstance(value, dict):
        raise OutboundRequestError("upstream JSON root must be an object")
    return value
