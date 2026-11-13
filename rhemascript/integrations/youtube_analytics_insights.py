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


def _period_days(query: dict[str, Any]) -> int:
    try:
        start = date.fromisoformat(query["startDate"])
        end = date.fromisoformat(query["endDate"])
    except (KeyError, TypeError, ValueError):
        raise YouTubeAnalyticsInsightError("snapshot query has an invalid date range") from None
    return (end - start).days + 1


def _metric_totals(snapshot: dict[str, Any]) -> dict[str, str] | None:
    report = snapshot["response"]
    rows = report.get("rows")
    if not rows:
        return None
    headers = report["columnHeaders"]
    metric_positions: list[tuple[str, int, str]] = []
    for index, header in enumerate(headers):
        if header["columnType"] != "METRIC":
            continue
        dtype = header["dataType"].upper()
        if dtype not in {"INTEGER", "FLOAT", "CURRENCY"}:
            raise YouTubeAnalyticsInsightError(
                f"metric {header['name']} has unsupported numeric data type {dtype}"
            )
        metric_positions.append((header["name"], index, dtype))
    totals: dict[str, Decimal] = {name: Decimal(0) for name, _, _ in metric_positions}
    for row_number, row in enumerate(rows):
        for name, index, dtype in metric_positions:
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
            if dtype == "INTEGER" and number != number.to_integral_value():
                raise YouTubeAnalyticsInsightError(
                    f"integer metric {name} contains a fractional value"
                )
            totals[name] += number
    return {name: format(value, "f") for name, value in totals.items()}


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
    current_days = _period_days(current_query)
    previous_days = _period_days(previous_query)
    if current_days != previous_days:
        raise YouTubeAnalyticsInsightError(
            "periods must have equal inclusive date-range lengths"
        )
    if current_query["startDate"] <= previous_query["endDate"]:
        raise YouTubeAnalyticsInsightError("current period must follow previous period")

    current_totals = _metric_totals(current_snapshot)
    previous_totals = _metric_totals(previous_snapshot)
    metrics: dict[str, Any] = {}
    names = set(current_totals or {}) | set(previous_totals or {})
    for name in sorted(names):
        current_value = Decimal(current_totals[name]) if current_totals is not None else None
        previous_value = Decimal(previous_totals[name]) if previous_totals is not None else None
        if current_value is None or previous_value is None:
            delta = change_pct = None
            status = "INSUFFICIENT_DATA"
        else:
            delta_value = current_value - previous_value
            delta = format(delta_value, "f")
            if previous_value == 0:
                change_pct = None
                status = "ZERO_BASELINE"
            else:
                change_pct = format((delta_value / abs(previous_value) * 100), "f")
                status = "COMPARABLE"
        metrics[name] = {
            "current_total": None if current_value is None else format(current_value, "f"),
            "previous_total": None if previous_value is None else format(previous_value, "f"),
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
            "data_status": "NO_DATA" if current_totals is None else "DATA_RETURNED",
        },
        "previous_period": {
            "start_date": previous_query["startDate"],
            "end_date": previous_query["endDate"],
            "days": previous_days,
            "returned_rows": previous_snapshot["row_count"],
            "data_status": "NO_DATA" if previous_totals is None else "DATA_RETURNED",
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


def verify_analytics_period_comparison(comparison: dict[str, Any]) -> bool:
    """Verify the comparison envelope digest and its metric status consistency."""
    if not isinstance(comparison, dict):
        raise YouTubeAnalyticsInsightError("comparison must be an object")
    if "comparison_sha256" not in comparison:
        raise YouTubeAnalyticsInsightError("comparison digest is missing")
    expected = {
        "schema_version", "evidence_type", "current_snapshot_sha256",
        "previous_snapshot_sha256", "current_period", "previous_period",
        "metrics", "interpretation", "comparison_sha256",
    }
    if set(comparison) != expected:
        raise YouTubeAnalyticsInsightError("comparison contains unsupported fields")
    body = {key: value for key, value in comparison.items() if key != "comparison_sha256"}
    if comparison["comparison_sha256"] != _canonical_digest(body):
        raise YouTubeAnalyticsInsightError("comparison digest does not match")
    if comparison["schema_version"] != "1.0" or comparison["evidence_type"] != "YOUTUBE_ANALYTICS_PERIOD_COMPARISON":
        raise YouTubeAnalyticsInsightError("comparison identity is unsupported")
    if not isinstance(comparison["metrics"], dict):
        raise YouTubeAnalyticsInsightError("comparison metrics must be an object")
    for name, metric in comparison["metrics"].items():
        if not isinstance(name, str) or not isinstance(metric, dict):
            raise YouTubeAnalyticsInsightError("comparison metric entry is malformed")
        if metric.get("status") not in {"COMPARABLE", "ZERO_BASELINE", "INSUFFICIENT_DATA"}:
            raise YouTubeAnalyticsInsightError("comparison metric status is invalid")
        if metric["status"] == "INSUFFICIENT_DATA" and (
            metric.get("absolute_change") is not None
            or metric.get("percentage_change") is not None
        ):
            raise YouTubeAnalyticsInsightError("insufficient-data metric cannot report a change")
        if metric["status"] == "ZERO_BASELINE" and metric.get("percentage_change") is not None:
            raise YouTubeAnalyticsInsightError("zero-baseline metric cannot report percentage change")
    return True
