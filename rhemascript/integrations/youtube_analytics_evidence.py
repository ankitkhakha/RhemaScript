"""Evidence-preserving adapter from YouTube Analytics reports to CAP-15."""
from __future__ import annotations

import math
from typing import Any


class YouTubeAnalyticsEvidenceError(ValueError):
    """Raised when an Analytics report cannot be safely linked to production."""


def build_cap15_performance_evidence(
    report: dict[str, Any], *, video_id: str, production_version: str,
    evidence_reference: str, video_filter: str,
) -> dict[str, Any]:
    """Convert one video-filtered Analytics report into descriptive CAP-15 evidence.

    The caller must supply the exact YouTube video ID, RhemaScript production
    version, and a durable reference to the retained source report. This helper
    never infers project linkage or causal effects.
    """
    for name, value in (("video_id", video_id), ("production_version", production_version),
                        ("evidence_reference", evidence_reference)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise YouTubeAnalyticsEvidenceError(f"{name} must be a non-empty exact string")
    if video_filter != f"video=={video_id}":
        raise YouTubeAnalyticsEvidenceError("video_filter must exactly bind the report to video_id")
    if not isinstance(report, dict):
        raise YouTubeAnalyticsEvidenceError("report must be an object")
    headers = report.get("columnHeaders")
    rows = report.get("rows", [])
    if not isinstance(headers, list) or not headers:
        raise YouTubeAnalyticsEvidenceError("report columnHeaders must be a non-empty list")
    if not isinstance(rows, list):
        raise YouTubeAnalyticsEvidenceError("report rows must be a list")
    columns: list[tuple[str, str]] = []
    seen: set[str] = set()
    for header in headers:
        if not isinstance(header, dict):
            raise YouTubeAnalyticsEvidenceError("each report column header must be an object")
        name, kind = header.get("name"), header.get("columnType")
        if (not isinstance(name, str) or not name.strip() or name in seen
                or kind not in ("DIMENSION", "METRIC")):
            raise YouTubeAnalyticsEvidenceError("report column header is invalid or duplicated")
        seen.add(name)
        columns.append((name, kind))
    observations = []
    for index, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != len(columns):
            raise YouTubeAnalyticsEvidenceError(f"report row {index} does not match its headers")
        dimensions: dict[str, Any] = {}
        metrics: dict[str, float] = {}
        for (name, kind), value in zip(columns, row):
            if kind == "DIMENSION":
                if not isinstance(value, (str, int, float)) or isinstance(value, bool):
                    raise YouTubeAnalyticsEvidenceError(f"dimension {name} has an invalid value")
                dimensions[name] = value
            else:
                if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                    raise YouTubeAnalyticsEvidenceError(f"metric {name} is not numeric")
                try:
                    number = float(value)
                except (TypeError, ValueError):
                    raise YouTubeAnalyticsEvidenceError(f"metric {name} is not numeric") from None
                if not math.isfinite(number) or number < 0:
                    raise YouTubeAnalyticsEvidenceError(f"metric {name} must be finite and non-negative")
                metrics[name] = number
        observations.append({
            "source": "YOUTUBE_ANALYTICS_API", "video_id": video_id,
            "production_version": production_version, "evidence_reference": evidence_reference,
            "dimensions": dimensions, "metrics": metrics, "video_filter": video_filter,
        })
    return {
        "linked_production_version": production_version,
        "performance_observations": observations,
        "source_report_reference": evidence_reference,
        "source_video_id": video_id,
        "causal_claims_allowed": False,
        "interpretation": "DESCRIPTIVE_ONLY",
    }
