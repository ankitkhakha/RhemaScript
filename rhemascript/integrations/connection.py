"""Dedicated read-only IF-18 YouTube connection verification command.

This module intentionally exposes no upload, thumbnail, metadata-write, scheduling,
or publishing operation. Its gateway binding contains only OAuth token refresh
and authenticated channel read operations.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sys
import uuid
from typing import Sequence

from rhemascript.integrations.audit import JsonlAuditSink
from rhemascript.integrations.youtube import (
    YouTubeClient,
    YouTubeConfig,
    YouTubeIntegrationError,
    youtube_provider_binding,
)
from rhemascript.interfaces.external import ExternalIntegrationGateway


def read_only_youtube_binding():
    """Return an IF-18 binding with no write-capable operations."""
    binding = youtube_provider_binding()
    return replace(
        binding,
        operations={
            name: spec
            for name, spec in binding.operations.items()
            if name in {"OAUTH_TOKEN", "CHANNEL_READ"}
        },
    )


def _fingerprint(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _identity_audit(sink, *, expected_channel_id: str,
                    actual_channel_id: str | None, matched: bool,
                    error_type: str | None = None) -> None:
    expected_fp = _fingerprint(expected_channel_id)
    actual_fp = _fingerprint(actual_channel_id) if actual_channel_id else "unavailable"
    sink({
        "interface_id": "IF-18",
        "provider": "youtube",
        "request_id": str(uuid.uuid4()),
        "project_id": "RHEMASCRIPT-CHANNEL-CONNECTION",
        "operation": "CHANNEL_IDENTITY_VERIFY",
        "method": "GET",
        "host": "www.googleapis.com",
        "request_fingerprint": _fingerprint(
            "IF-18|CHANNEL_IDENTITY_VERIFY|" + expected_fp + "|" + actual_fp
        ),
        "request_bytes": 0,
        "phase": "COMPLETED" if matched else "FAILED",
        **({"error_type": error_type} if error_type else {}),
    })


def run_connection_check(credential_file: str | Path,
                         expected_channel_id: str,
                         audit_file: str | Path,
                         *, transport=None) -> dict[str, object]:
    """Load protected credentials, verify IF-18 channel identity, and audit safely.

    The optional transport parameter is a test seam. The operator CLI never
    accepts or constructs a custom transport.
    """
    if not isinstance(expected_channel_id, str) or not expected_channel_id.strip():
        raise YouTubeIntegrationError("an expected channel ID is required")
    if expected_channel_id != expected_channel_id.strip():
        raise YouTubeIntegrationError("expected channel ID must not contain surrounding whitespace")

    sink = JsonlAuditSink(audit_file)
    expected_fp = _fingerprint(expected_channel_id)
    try:
        config = YouTubeConfig.from_private_file(credential_file)
        gateway = ExternalIntegrationGateway(
            (read_only_youtube_binding(),),
            transport=transport,
            credential_resolver=lambda _provider: {},
            audit_sink=sink,
            enabled=True,
        )
        client = YouTubeClient(config, gateway=gateway)
        verified = client.verify_connection(expected_channel_id=expected_channel_id)
        actual_id = verified.get("channel_id")
        if not isinstance(actual_id, str) or not actual_id:
            raise YouTubeIntegrationError("channel verification returned no valid identity")
        _identity_audit(
            sink,
            expected_channel_id=expected_channel_id,
            actual_channel_id=actual_id,
            matched=True,
        )
        return {
            "status": "CONNECTED",
            "interface_id": "IF-18",
            "identity": "MATCH",
            "read_only": True,
            "publishing_enabled": False,
            "channel_id": "REDACTED",
            "channel_title": "REDACTED",
            "audit": "RECORDED",
        }
    except Exception as exc:
        # The audit schema stores only fingerprints and exception class names.
        _identity_audit(
            sink,
            expected_channel_id=expected_channel_id,
            actual_channel_id=None,
            matched=False,
            error_type=type(exc).__name__,
        )
        if isinstance(exc, YouTubeIntegrationError):
            raise
        raise YouTubeIntegrationError(
            "read-only YouTube connection verification failed; inspect the redacted audit record"
        ) from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the expected YouTube channel through IF-18 (read-only)"
    )
    parser.add_argument("--credential-file", required=True,
                        help="path to the existing owner-only OAuth credential JSON file")
    parser.add_argument("--expected-channel-id", required=True,
                        help="exact channel ID from the channel owner's records")
    parser.add_argument("--audit-file", required=True,
                        help="JSONL audit path inside an existing private directory")
    args = parser.parse_args(argv)
    try:
        result = run_connection_check(
            args.credential_file, args.expected_channel_id, args.audit_file
        )
    except (YouTubeIntegrationError, KeyboardInterrupt):
        print(json.dumps({
            "status": "FAILED",
            "interface_id": "IF-18",
            "read_only": True,
            "publishing_enabled": False,
            "details": "See redacted local audit record; no credential values are displayed.",
        }, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
