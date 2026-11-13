"""Content-addressed, offline YouTube Analytics report evidence snapshots.

This module never calls Google or writes files. It binds the exact query,
retrieval timestamp and validated response into a deterministic digest.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from rhemascript.integrations.youtube import (
    YouTubeIntegrationError,
    _validate_analytics_report,
    _validate_analytics_request,
)


class YouTubeAnalyticsEvidenceError(ValueError):
    """Invalid or tampered Analytics evidence snapshot."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise YouTubeAnalyticsEvidenceError(
            "Analytics evidence must contain finite JSON-compatible values"
        ) from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _retrieval_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise YouTubeAnalyticsEvidenceError(
            "retrieved_at must be a timezone-aware datetime"
        )
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_analytics_evidence_snapshot(
    *,
    params: dict[str, Any],
    report: dict[str, Any],
    retrieved_at: datetime,
) -> dict[str, Any]:
    """Build a hash-bound snapshot from a validated query and response.

    report must be the exact decoded JSON response returned by the provider.
    The caller is responsible for recording the actual retrieval timestamp.
    """
    try:
        _validate_analytics_request(params)
        _validate_analytics_report(report, params)
    except YouTubeIntegrationError as exc:
        raise YouTubeAnalyticsEvidenceError(str(exc)) from None

    timestamp = _retrieval_timestamp(retrieved_at)
    query_copy = deepcopy(params)
    response_copy = deepcopy(report)
    response_digest = _digest(response_copy)
    body = {
        "schema_version": "1.0",
        "evidence_type": "YOUTUBE_ANALYTICS_REPORT_SNAPSHOT",
        "source": "youtubeanalytics.googleapis.com/v2/reports",
        "operation": "reports.query",
        "retrieved_at": timestamp,
        "query": query_copy,
        "response": response_copy,
        "row_count": len(response_copy.get("rows", [])),
        "no_data": not bool(response_copy.get("rows", [])),
        "response_sha256": response_digest,
    }
    body["snapshot_sha256"] = _digest(body)
    return body


def verify_analytics_evidence_snapshot(snapshot: dict[str, Any]) -> bool:
    """Verify exact snapshot shape, request/response contracts and both digests."""
    if not isinstance(snapshot, dict):
        raise YouTubeAnalyticsEvidenceError("snapshot must be an object")
    expected = {
        "schema_version", "evidence_type", "source", "operation", "retrieved_at",
        "query", "response", "row_count", "no_data", "response_sha256",
        "snapshot_sha256",
    }
    if set(snapshot) != expected:
        raise YouTubeAnalyticsEvidenceError("snapshot contains missing or unsupported fields")
    if (snapshot.get("schema_version") != "1.0"
            or snapshot.get("evidence_type") != "YOUTUBE_ANALYTICS_REPORT_SNAPSHOT"
            or snapshot.get("source") != "youtubeanalytics.googleapis.com/v2/reports"
            or snapshot.get("operation") != "reports.query"):
        raise YouTubeAnalyticsEvidenceError("snapshot identity or schema is unsupported")
    try:
        timestamp = datetime.fromisoformat(
            snapshot["retrieved_at"].replace("Z", "+00:00")
        )
        _retrieval_timestamp(timestamp)
        _validate_analytics_request(snapshot["query"])
        _validate_analytics_report(snapshot["response"], snapshot["query"])
    except (KeyError, TypeError, ValueError, YouTubeIntegrationError):
        raise YouTubeAnalyticsEvidenceError("snapshot metadata or report contract is invalid") from None

    response_digest = _digest(snapshot["response"])
    if snapshot["response_sha256"] != response_digest:
        raise YouTubeAnalyticsEvidenceError("Analytics response digest does not match")
    rows = snapshot["response"].get("rows", [])
    if (snapshot["row_count"] != len(rows)
            or snapshot["no_data"] is not (not bool(rows))):
        raise YouTubeAnalyticsEvidenceError("Analytics row metadata does not match response")
    body = {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
    if snapshot["snapshot_sha256"] != _digest(body):
        raise YouTubeAnalyticsEvidenceError("Analytics snapshot digest does not match")
    return True
