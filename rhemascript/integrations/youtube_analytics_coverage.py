"""Daily date-coverage diagnostics for verified YouTube Analytics snapshots.

Coverage describes which day labels were returned. It does not impute absent
days as zero or assert why the provider omitted them.
"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from rhemascript.integrations.youtube_analytics_evidence import (
    YouTubeAnalyticsEvidenceError,
    verify_analytics_evidence_snapshot,
)
from rhemascript.integrations.youtube_analytics_insights import (
    YouTubeAnalyticsInsightError,
    _canonical_digest,
)


class YouTubeAnalyticsCoverageError(ValueError):
    """Invalid snapshot or non-daily report for date-coverage analysis."""


def diagnose_daily_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
    """List returned, missing, internal-gap and trailing-gap dates for a day report."""
    try:
        verify_analytics_evidence_snapshot(snapshot)
    except YouTubeAnalyticsEvidenceError as exc:
        raise YouTubeAnalyticsCoverageError(f"unverified snapshot: {exc}") from None

    query = snapshot["query"]
    dimensions = query.get("dimensions", "")
    dimension_names = [item.strip() for item in dimensions.split(",") if item.strip()]
    if "day" not in dimension_names:
        raise YouTubeAnalyticsCoverageError("daily coverage requires the day dimension")
    day_column = dimension_names.index("day")
    if day_column >= len(snapshot["response"]["columnHeaders"]):
        raise YouTubeAnalyticsCoverageError("day dimension column is missing")

    try:
        start = date.fromisoformat(query["startDate"])
        end = date.fromisoformat(query["endDate"])
    except (KeyError, TypeError, ValueError):
        raise YouTubeAnalyticsCoverageError("snapshot date range is invalid") from None

    returned: set[date] = set()
    rows = snapshot["response"].get("rows", [])
    for row_number, row in enumerate(rows):
        raw_day = row[day_column]
        if not isinstance(raw_day, str):
            raise YouTubeAnalyticsCoverageError(f"day value in row {row_number} is not a string")
        try:
            parsed = date.fromisoformat(raw_day)
        except ValueError:
            raise YouTubeAnalyticsCoverageError(f"day value in row {row_number} is not an ISO date") from None
        if parsed.isoformat() != raw_day or parsed < start or parsed > end:
            raise YouTubeAnalyticsCoverageError(f"day value in row {row_number} is outside the requested range")
        returned.add(parsed)

    expected: set[date] = set()
    cursor = start
    while cursor <= end:
        expected.add(cursor)
        cursor += timedelta(days=1)
    missing = sorted(expected - returned)
    first_returned = min(returned) if returned else None
    last_returned = max(returned) if returned else None
    internal_gaps = [
        day for day in missing
        if first_returned is not None and last_returned is not None
        and first_returned < day < last_returned
    ]
    trailing_gaps = [
        day for day in missing
        if last_returned is not None and day > last_returned
    ]
    leading_gaps = [
        day for day in missing
        if first_returned is not None and day < first_returned
    ]

    body = {
        "schema_version": "1.0",
        "evidence_type": "YOUTUBE_ANALYTICS_DAILY_COVERAGE_DIAGNOSTIC",
        "source_snapshot_sha256": snapshot["snapshot_sha256"],
        "retrieved_at": snapshot["retrieved_at"],
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "expected_days": len(expected),
        "returned_rows": len(rows),
        "distinct_returned_days": len(returned),
        "returned_dates": [day.isoformat() for day in sorted(returned)],
        "missing_dates": [day.isoformat() for day in missing],
        "leading_gap_dates": [day.isoformat() for day in leading_gaps],
        "internal_gap_dates": [day.isoformat() for day in internal_gaps],
        "trailing_gap_dates": [day.isoformat() for day in trailing_gaps],
        "coverage_ratio": format(len(returned) / len(expected), ".6f"),
        "interpretation": (
            "Coverage counts distinct day labels present in the returned report. "
            "Missing dates are unknown/not returned, not zero activity. "
            "This diagnostic does not infer reporting delay, cause, or completeness."
        ),
    }
    body["diagnostic_sha256"] = _canonical_digest(body)
    return body


def verify_daily_coverage_diagnostic(
    diagnostic: dict[str, Any], snapshot: dict[str, Any]
) -> bool:
    """Recompute a diagnostic from its exact source snapshot and compare all fields."""
    if not isinstance(diagnostic, dict):
        raise YouTubeAnalyticsCoverageError("diagnostic must be an object")
    expected = diagnose_daily_coverage(snapshot)
    if diagnostic != expected:
        raise YouTubeAnalyticsCoverageError("coverage diagnostic does not match its source snapshot")
    return True
