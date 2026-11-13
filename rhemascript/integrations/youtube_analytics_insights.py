"""Deterministic, evidence-bound YouTube Analytics period comparisons.

This module performs arithmetic over verified snapshots only. It does not
retrieve data, infer missing rows as zero, generate recommendations, or act
on a YouTube account.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import date
from decimal import Decimal, InvalidOperation
import hashlib
import json
from typing import Any

from rhemascript.integrations.youtube_analytics_evidence import (
    YouTubeAnalyticsEvidenceError,
    verify_analytics_evidence_snapshot,
)


class YouTubeAnalyticsInsightError(ValueError):
    """Invalid or incomparable Analytics evidence."""


def _canonical_digest(value: Any) -> str:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise YouTubeAnalyticsInsightError("comparison contains invalid JSON values") from None
    return hashlib.sha256(raw).hexdigest()


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    return format(value.normalize(), "f")


def _period_days(query: dict[str, Any]) -> int:
    try:
        start = date.fromisoformat(query["startDate"])
        end = date.fromisoformat(query["endDate"])
    except (KeyError, TypeError, ValueError):
        raise YouTubeAnalyticsInsightError("snapshot query has an invalid date range") from None
    return (end - start).days + 1


_ADDITIVE_METRICS = {
    "views", "estimatedMinutesWatched", "subscribersGained", "subscribersLost",
    "likes", "dislikes", "comments", "shares", "videosAddedToPlaylists",
    "videosRemovedFromPlaylists", "playlistStarts",
}


def _metric_values(snapshot: dict[str, Any]) -> dict[str, tuple[Decimal | None, str]] | None:
    report = snapshot["response"]
    rows = report.get("rows")
    if not rows:
        return None
    headers = report["columnHeaders"]
    positions: dict[str, tuple[int, str]] = {}
    for index, header in enumerate(headers):
        if header["columnType"] != "METRIC":
            continue
        name = header["name"]
        dtype = header["dataType"].upper()
        if dtype not in {"INTEGER", "FLOAT", "CURRENCY"}:
            raise YouTubeAnalyticsInsightError(
                f"metric {name} has unsupported numeric data type {dtype}"
            )
        if name != "averageViewDuration" and name not in _ADDITIVE_METRICS:
            raise YouTubeAnalyticsInsightError(
                f"metric {name} has no V1 aggregation contract"
            )
        positions[name] = (index, dtype)

    totals: dict[str, Decimal] = {}
    for name, (index, dtype) in positions.items():
        if name == "averageViewDuration":
            for row_number, row in enumerate(rows):
                value = row[index]
                if isinstance(value, bool) or not isinstance(value, (int, float, str)):
                    raise YouTubeAnalyticsInsightError(
                        f"metric {name} in row {row_number} is not a numeric scalar"
                    )
                try:
                    number = Decimal(str(value))
                except InvalidOperation:
                    raise YouTubeAnalyticsInsightError(
                        f"metric {name} in row {row_number} is not numeric"
                    ) from None
                if not number.is_finite():
                    raise YouTubeAnalyticsInsightError(
                        f"metric {name} in row {row_number} is not finite"
                    )
                if number < 0:
                    raise YouTubeAnalyticsInsightError(
                        f"metric {name} in row {row_number} is negative"
                    )
            continue
        total = Decimal(0)
        for row_number, row in enumerate(rows):
            value = row[index]
            if isinstance(value, bool) or not isinstance(value, (int, float, str)):
                raise YouTubeAnalyticsInsightError(
                    f"metric {name} in row {row_number} is not a numeric scalar"
                )
            try:
                number = Decimal(str(value))
            except InvalidOperation:
                raise YouTubeAnalyticsInsightError(
                    f"metric {name} in row {row_number} is not numeric"
                ) from None
            if not number.is_finite():
                raise YouTubeAnalyticsInsightError(
                    f"metric {name} in row {row_number} is not finite"
                )
            if number < 0:
                raise YouTubeAnalyticsInsightError(
                    f"metric {name} in row {row_number} is negative"
                )
            if dtype == "INTEGER" and number != number.to_integral_value():
                raise YouTubeAnalyticsInsightError(
                    f"integer metric {name} contains a fractional value"
                )
            total += number
        totals[name] = total

    values: dict[str, tuple[Decimal | None, str]] = {
        name: (value, "SUM") for name, value in totals.items()
    }
    if "averageViewDuration" in positions:
        if not {"views", "estimatedMinutesWatched"}.issubset(totals):
            raise YouTubeAnalyticsInsightError(
                "averageViewDuration requires views and estimatedMinutesWatched "
                "in the same query for a weighted period average"
            )
        views = totals["views"]
        average = (
            None if views == 0
            else totals["estimatedMinutesWatched"] * Decimal(60) / views
        )
        values["averageViewDuration"] = (average, "WEIGHTED_AVERAGE_SECONDS")
    return values


def _daily_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Report returned day keys and unobserved calendar dates without imputing values."""
    query = snapshot["query"]
    dimensions = query.get("dimensions", "").split(",") if query.get("dimensions") else []
    if "day" not in dimensions:
        return {
            "status": "NOT_APPLICABLE",
            "expected_calendar_days": None,
            "observed_days": [],
            "unobserved_days": [],
            "unobserved_day_count": None,
            "interpretation": (
                "The report does not include the day dimension; calendar-day coverage "
                "cannot be assessed from this query."
            ),
        }
    start = date.fromisoformat(query["startDate"])
    end = date.fromisoformat(query["endDate"])
    headers = snapshot["response"]["columnHeaders"]
    day_columns = [
        index for index, header in enumerate(headers)
        if header["columnType"] == "DIMENSION" and header["name"] == "day"
    ]
    if len(day_columns) != 1:
        raise YouTubeAnalyticsInsightError("daily report must contain exactly one day column")
    day_index = day_columns[0]
    observed: set[date] = set()
    for row_number, row in enumerate(snapshot["response"].get("rows") or []):
        value = row[day_index]
        if not isinstance(value, str):
            raise YouTubeAnalyticsInsightError(
                f"day dimension in row {row_number} must be a string"
            )
        try:
            parsed = date.fromisoformat(value)
        except ValueError:
            raise YouTubeAnalyticsInsightError(
                f"day dimension in row {row_number} is not an ISO date"
            ) from None
        if parsed.isoformat() != value:
            raise YouTubeAnalyticsInsightError(
                f"day dimension in row {row_number} is not canonical ISO format"
            )
        if parsed < start or parsed > end:
            raise YouTubeAnalyticsInsightError(
                f"day dimension in row {row_number} is outside the requested range"
            )
        if len(dimensions) == 1 and parsed in observed:
            raise YouTubeAnalyticsInsightError(
                f"duplicate day dimension value: {value}"
            )
        observed.add(parsed)

    expected = {
        start.fromordinal(ordinal)
        for ordinal in range(start.toordinal(), end.toordinal() + 1)
    }
    unobserved = sorted(expected - observed)
    return {
        "status": "NO_ROWS_RETURNED" if not observed else "OBSERVATION_ONLY",
        "expected_calendar_days": len(expected),
        "observed_days": [value.isoformat() for value in sorted(observed)],
        "unobserved_days": [value.isoformat() for value in unobserved],
        "unobserved_day_count": len(unobserved),
        "interpretation": (
            "Unobserved dates are not zero-activity dates. Reporting delays or API "
            "row omission may explain absent dates; this diagnostic makes no claim "
            "about completeness or the reason for omission."
        ),
    }


def _query_identity(query: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in query.items()
        if key not in {"startDate", "endDate"}
    }


def compare_analytics_periods(
    current_snapshot: dict[str, Any],
    previous_snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Compare equal-length, identically scoped, hash-verified report periods."""
    try:
        verify_analytics_evidence_snapshot(current_snapshot)
        verify_analytics_evidence_snapshot(previous_snapshot)
    except YouTubeAnalyticsEvidenceError as exc:
        raise YouTubeAnalyticsInsightError(f"unverified snapshot: {exc}") from None

    current_query = current_snapshot["query"]
    previous_query = previous_snapshot["query"]
    if _query_identity(current_query) != _query_identity(previous_query):
        raise YouTubeAnalyticsInsightError(
            "periods must use identical channel, metrics, dimensions and filters"
        )
    if current_query["startDate"] <= previous_query["endDate"]:
        raise YouTubeAnalyticsInsightError("current period must follow previous period")
    current_days = _period_days(current_query)
    previous_days = _period_days(previous_query)
    if current_days != previous_days:
        raise YouTubeAnalyticsInsightError(
            "periods must have equal inclusive date-range lengths"
        )

    current_values = _metric_values(current_snapshot)
    previous_values = _metric_values(previous_snapshot)
    metrics: dict[str, Any] = {}
    names = set(current_values or {}) | set(previous_values or {})
    for name in sorted(names):
        current_entry = current_values.get(name) if current_values is not None else None
        previous_entry = previous_values.get(name) if previous_values is not None else None
        aggregation = (current_entry or previous_entry)[1]
        current_value = current_entry[0] if current_entry is not None else None
        previous_value = previous_entry[0] if previous_entry is not None else None
        if current_values is None or previous_values is None:
            delta = change_pct = None
            status = "INSUFFICIENT_DATA"
        elif current_value is None or previous_value is None:
            delta = change_pct = None
            status = "ZERO_DENOMINATOR"
        else:
            delta_value = current_value - previous_value
            delta = _decimal_text(delta_value)
            if previous_value == 0:
                change_pct = None
                status = "ZERO_BASELINE"
            else:
                change_pct = _decimal_text(delta_value / previous_value * 100)
                status = "COMPARABLE"
        metrics[name] = {
            "aggregation": aggregation,
            "current_value": None if current_value is None else _decimal_text(current_value),
            "previous_value": None if previous_value is None else _decimal_text(previous_value),
            "absolute_change": delta,
            "percentage_change": change_pct,
            "status": status,
        }

    body = {
        "schema_version": "1.0",
        "evidence_type": "YOUTUBE_ANALYTICS_PERIOD_COMPARISON",
        "current_snapshot_sha256": current_snapshot["snapshot_sha256"],
        "previous_snapshot_sha256": previous_snapshot["snapshot_sha256"],
        "current_period": {
            "start_date": current_query["startDate"],
            "end_date": current_query["endDate"],
            "days": current_days,
            "returned_rows": current_snapshot["row_count"],
            "data_status": "NO_DATA" if current_values is None else "DATA_RETURNED",
            "daily_coverage": _daily_coverage(current_snapshot),
        },
        "previous_period": {
            "start_date": previous_query["startDate"],
            "end_date": previous_query["endDate"],
            "days": previous_days,
            "returned_rows": previous_snapshot["row_count"],
            "data_status": "NO_DATA" if previous_values is None else "DATA_RETURNED",
            "daily_coverage": _daily_coverage(previous_snapshot),
        },
        "metrics": metrics,
        "interpretation": (
            "Observed totals from returned rows only. Missing rows are not imputed as zero. "
            "Percentage change is omitted for a zero baseline or insufficient data. "
            "This comparison is descriptive, not causal, and is not a recommendation."
        ),
    }
    body["comparison_sha256"] = _canonical_digest(body)
    return body


def verify_analytics_period_comparison(
    comparison: dict[str, Any],
    current_snapshot: dict[str, Any] | None = None,
    previous_snapshot: dict[str, Any] | None = None,
) -> bool:
    """Verify digest, internal metric arithmetic, and optionally exact source derivation.

    A digest alone proves only consistency with the supplied envelope. When the
    source snapshots are available, recompute the entire comparison and require
    an exact match to establish derivation from those verified snapshots.
    """
    if not isinstance(comparison, dict):
        raise YouTubeAnalyticsInsightError("comparison must be an object")
    expected = {
        "schema_version", "evidence_type", "current_snapshot_sha256",
        "previous_snapshot_sha256", "current_period", "previous_period",
        "metrics", "interpretation", "comparison_sha256",
    }
    if set(comparison) != expected:
        raise YouTubeAnalyticsInsightError("comparison contains unsupported or missing fields")
    digest = comparison["comparison_sha256"]
    if (not isinstance(digest, str) or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)):
        raise YouTubeAnalyticsInsightError("comparison digest is not a lowercase SHA-256 value")
    body = {key: value for key, value in comparison.items() if key != "comparison_sha256"}
    if digest != _canonical_digest(body):
        raise YouTubeAnalyticsInsightError("comparison digest does not match")
    if comparison["schema_version"] != "1.0" or comparison["evidence_type"] != "YOUTUBE_ANALYTICS_PERIOD_COMPARISON":
        raise YouTubeAnalyticsInsightError("comparison identity is unsupported")
    for field in ("current_snapshot_sha256", "previous_snapshot_sha256"):
        value = comparison[field]
        if (not isinstance(value, str) or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)):
            raise YouTubeAnalyticsInsightError(f"{field} is not a lowercase SHA-256 value")
    if not isinstance(comparison["interpretation"], str):
        raise YouTubeAnalyticsInsightError("comparison interpretation must be text")

    for period_name in ("current_period", "previous_period"):
        period = comparison[period_name]
        if not isinstance(period, dict) or not {
            "start_date", "end_date", "days", "returned_rows", "data_status", "daily_coverage"
        } == set(period):
            raise YouTubeAnalyticsInsightError(f"{period_name} has an invalid structure")
        try:
            start_date = date.fromisoformat(period["start_date"])
            end_date = date.fromisoformat(period["end_date"])
        except (TypeError, ValueError):
            raise YouTubeAnalyticsInsightError(f"{period_name} has invalid dates") from None
        if (start_date.isoformat() != period["start_date"]
                or end_date.isoformat() != period["end_date"]
                or end_date < start_date
                or period["days"] != (end_date - start_date).days + 1
                or isinstance(period["days"], bool)
                or not isinstance(period["returned_rows"], int)
                or isinstance(period["returned_rows"], bool)
                or period["returned_rows"] < 0
                or period["data_status"] not in {"NO_DATA", "DATA_RETURNED"}
                or (period["data_status"] == "NO_DATA") != (period["returned_rows"] == 0)
                or not isinstance(period["daily_coverage"], dict)):
            raise YouTubeAnalyticsInsightError(f"{period_name} fields are inconsistent")
    current_period = comparison["current_period"]
    previous_period = comparison["previous_period"]
    if (current_period["days"] != previous_period["days"]
            or current_period["start_date"] <= previous_period["end_date"]):
        raise YouTubeAnalyticsInsightError("comparison periods are not equal-length and chronological")

    metrics = comparison["metrics"]
    if not isinstance(metrics, dict):
        raise YouTubeAnalyticsInsightError("comparison metrics must be an object")
    metric_fields = {
        "aggregation", "current_value", "previous_value",
        "absolute_change", "percentage_change", "status",
    }
    allowed_names = _ADDITIVE_METRICS | {"averageViewDuration"}
    for name, metric in metrics.items():
        if name not in allowed_names or not isinstance(metric, dict) or set(metric) != metric_fields:
            raise YouTubeAnalyticsInsightError("comparison metric entry is malformed")
        expected_aggregation = "WEIGHTED_AVERAGE_SECONDS" if name == "averageViewDuration" else "SUM"
        if metric["aggregation"] != expected_aggregation:
            raise YouTubeAnalyticsInsightError("comparison metric aggregation is invalid")
        status = metric["status"]
        if status not in {"COMPARABLE", "ZERO_BASELINE", "INSUFFICIENT_DATA", "ZERO_DENOMINATOR"}:
            raise YouTubeAnalyticsInsightError("comparison metric status is invalid")
        parsed: dict[str, Decimal | None] = {}
        for field in ("current_value", "previous_value", "absolute_change", "percentage_change"):
            value = metric[field]
            if value is None:
                parsed[field] = None
                continue
            if not isinstance(value, str):
                raise YouTubeAnalyticsInsightError(f"comparison metric {field} must be decimal text or null")
            try:
                number = Decimal(value)
            except InvalidOperation:
                raise YouTubeAnalyticsInsightError(f"comparison metric {field} is not decimal text") from None
            if not number.is_finite() or _decimal_text(number) != value:
                raise YouTubeAnalyticsInsightError(f"comparison metric {field} is not canonical finite decimal text")
            parsed[field] = number
        current_value, previous_value = parsed["current_value"], parsed["previous_value"]
        delta, pct = parsed["absolute_change"], parsed["percentage_change"]
        if status == "INSUFFICIENT_DATA":
            if (delta is not None or pct is not None
                    or (current_value is not None and previous_value is not None)):
                raise YouTubeAnalyticsInsightError("insufficient-data metric has inconsistent values")
        elif status == "ZERO_DENOMINATOR":
            if (name != "averageViewDuration" or delta is not None or pct is not None
                    or (current_value is not None and previous_value is not None)):
                raise YouTubeAnalyticsInsightError("zero-denominator metric has inconsistent values")
        else:
            if current_value is None or previous_value is None or delta != current_value - previous_value:
                raise YouTubeAnalyticsInsightError("comparison metric absolute change is inconsistent")
            if status == "ZERO_BASELINE":
                if previous_value != 0 or pct is not None:
                    raise YouTubeAnalyticsInsightError("zero-baseline metric is inconsistent")
            elif previous_value == 0 or pct is None:
                raise YouTubeAnalyticsInsightError("comparable metric percentage change is inconsistent")
            else:
                # Canonical serialization can round weighted-average values.
                # Use a tight relative tolerance for arithmetic over those values.
                expected_pct = delta / previous_value * Decimal(100)
                tolerance = max(Decimal(1), abs(expected_pct)) * Decimal("1e-24")
                if abs(pct - expected_pct) > tolerance:
                    raise YouTubeAnalyticsInsightError("comparable metric percentage change is inconsistent")

    if (current_snapshot is None) != (previous_snapshot is None):
        raise YouTubeAnalyticsInsightError("both exact source snapshots are required for derivation verification")
    if current_snapshot is not None and previous_snapshot is not None:
        recomputed = compare_analytics_periods(current_snapshot, previous_snapshot)
        if recomputed != comparison:
            raise YouTubeAnalyticsInsightError("comparison does not match its exact source snapshots")
    return True
