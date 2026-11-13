import unittest
from copy import deepcopy
from datetime import datetime, timezone

from rhemascript.integrations.youtube_analytics_evidence import build_analytics_evidence_snapshot
from rhemascript.integrations.youtube_analytics_insights import (
    YouTubeAnalyticsInsightError,
    compare_analytics_periods,
    verify_analytics_period_comparison,
)


HEADERS = [
    {"name": "day", "dataType": "STRING", "columnType": "DIMENSION"},
    {"name": "country", "dataType": "STRING", "columnType": "DIMENSION"},
    {"name": "views", "dataType": "INTEGER", "columnType": "METRIC"},
    {"name": "estimatedMinutesWatched", "dataType": "FLOAT", "columnType": "METRIC"},
    {"name": "averageViewDuration", "dataType": "FLOAT", "columnType": "METRIC"},
    {"name": "subscribersGained", "dataType": "INTEGER", "columnType": "METRIC"},
]


def snapshot(start, end, rows, *, metrics="views,estimatedMinutesWatched,averageViewDuration,subscribersGained",
             dimensions="day", filters=None):
    params = {
        "ids": "channel==MINE", "startDate": start, "endDate": end,
        "metrics": metrics, "dimensions": dimensions,
    }
    if filters is not None:
        params["filters"] = filters
    requested_metrics = set(metrics.split(","))
    requested_dimensions = set(dimensions.split(",")) if dimensions else set()
    selected_headers = [
        header for header in HEADERS
        if (
            header["columnType"] == "DIMENSION"
            and header["name"] in requested_dimensions
        ) or (
            header["columnType"] == "METRIC"
            and header["name"] in requested_metrics
        )
    ]
    report = {"kind": "youtubeAnalytics#resultTable", "columnHeaders": selected_headers}
    if rows is not None:
        report["rows"] = deepcopy(rows)
    return build_analytics_evidence_snapshot(
        params=params, report=report,
        retrieved_at=datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc),
    )


class YouTubeAnalyticsInsightsTests(unittest.TestCase):
    def test_compares_equal_length_periods_and_binds_source_digests(self):
        previous = snapshot("2026-10-01", "2026-10-07", [
            ["2026-10-01", 10, 2.5, 15.0, 1],
            ["2026-10-02", 20, 4.5, 13.5, 2],
        ])
        current = snapshot("2026-10-08", "2026-10-14", [
            ["2026-10-08", 15, 3.0, 12.0, 1],
            ["2026-10-09", 30, 6.0, 12.0, 3],
        ])
        result = compare_analytics_periods(current, previous)
        self.assertEqual(result["metrics"]["views"]["current_value"], "45")
        self.assertEqual(result["metrics"]["views"]["previous_value"], "30")
        self.assertEqual(result["metrics"]["views"]["absolute_change"], "15")
        self.assertEqual(result["metrics"]["views"]["percentage_change"], "50")
        self.assertEqual(result["metrics"]["views"]["status"], "COMPARABLE")
        self.assertEqual(result["metrics"]["views"]["aggregation"], "SUM")
        self.assertEqual(result["metrics"]["averageViewDuration"]["aggregation"], "WEIGHTED_AVERAGE_SECONDS")
        self.assertEqual(result["metrics"]["averageViewDuration"]["current_value"], "12")
        self.assertEqual(result["metrics"]["averageViewDuration"]["previous_value"], "14")
        self.assertEqual(result["metrics"]["averageViewDuration"]["absolute_change"], "-2")
        self.assertEqual(result["current_snapshot_sha256"], current["snapshot_sha256"])
        self.assertEqual(result["previous_snapshot_sha256"], previous["snapshot_sha256"])
        self.assertTrue(verify_analytics_period_comparison(result))

    def test_daily_coverage_marks_unreturned_dates_without_zero_imputation(self):
        previous = snapshot("2026-10-01", "2026-10-07", [
            ["2026-10-01", 10, 2.5, 15.0, 1],
            ["2026-10-03", 20, 4.5, 13.5, 2],
        ])
        current = snapshot("2026-10-08", "2026-10-14", [
            ["2026-10-08", 15, 3.0, 12.0, 1],
            ["2026-10-09", 30, 6.0, 12.0, 3],
        ])
        result = compare_analytics_periods(current, previous)
        coverage = result["previous_period"]["daily_coverage"]
        self.assertEqual(coverage["expected_calendar_days"], 7)
        self.assertEqual(coverage["observed_days"], ["2026-10-01", "2026-10-03"])
        self.assertEqual(coverage["unobserved_day_count"], 5)
        self.assertEqual(coverage["status"], "OBSERVATION_ONLY")
        self.assertIn("not zero-activity", coverage["interpretation"])

    def test_reports_without_day_dimension_mark_coverage_not_applicable(self):
        previous = snapshot(
            "2026-10-01", "2026-10-07", [[10, 2.5, 15.0, 1]],
            dimensions="",
        )
        current = snapshot(
            "2026-10-08", "2026-10-14", [[15, 3.0, 12.0, 1]],
            dimensions="",
        )
        result = compare_analytics_periods(current, previous)
        self.assertEqual(
            result["current_period"]["daily_coverage"]["status"],
            "NOT_APPLICABLE",
        )
        self.assertIsNone(
            result["previous_period"]["daily_coverage"]["expected_calendar_days"]
        )

    def test_multi_dimension_daily_rows_count_distinct_days(self):
        metrics = "views,estimatedMinutesWatched,averageViewDuration,subscribersGained"
        previous = snapshot(
            "2026-10-01", "2026-10-07",
            [["2026-10-01", "US", 10, 2.5, 15.0, 1],
             ["2026-10-01", "CA", 5, 1.0, 12.0, 0],
             ["2026-10-03", "US", 20, 4.5, 13.5, 2]],
            metrics=metrics, dimensions="day,country",
        )
        current = snapshot(
            "2026-10-08", "2026-10-14",
            [["2026-10-08", "US", 15, 3.0, 12.0, 1],
             ["2026-10-08", "CA", 7, 1.5, 11.0, 0]],
            metrics=metrics, dimensions="day,country",
        )
        result = compare_analytics_periods(current, previous)
        coverage = result["previous_period"]["daily_coverage"]
        self.assertEqual(coverage["observed_days"], ["2026-10-01", "2026-10-03"])
        self.assertEqual(coverage["unobserved_day_count"], 5)

    def test_duplicate_day_rows_are_rejected(self):
        previous = snapshot("2026-10-01", "2026-10-07", [
            ["2026-10-01", 10, 2.5, 15.0, 1],
            ["2026-10-01", 20, 4.5, 13.5, 2],
        ])
        current = snapshot("2026-10-08", "2026-10-14", [
            ["2026-10-08", 15, 3.0, 12.0, 1],
        ])
        with self.assertRaisesRegex(YouTubeAnalyticsInsightError, "duplicate day"):
            compare_analytics_periods(current, previous)

    def test_day_outside_requested_range_is_rejected(self):
        previous = snapshot("2026-10-01", "2026-10-07", [
            ["2026-09-30", 10, 2.5, 15.0, 1],
        ])
        current = snapshot("2026-10-08", "2026-10-14", [
            ["2026-10-08", 15, 3.0, 12.0, 1],
        ])
        with self.assertRaisesRegex(YouTubeAnalyticsInsightError, "outside the requested range"):
            compare_analytics_periods(current, previous)

    def test_zero_baseline_has_no_percentage_change(self):
        previous = snapshot("2026-10-01", "2026-10-01", [["2026-10-01", 0, 0.0, 0.0, 0]])
        current = snapshot("2026-10-02", "2026-10-02", [["2026-10-02", 5, 1.0, 12.0, 1]])
        result = compare_analytics_periods(current, previous)
        self.assertEqual(result["metrics"]["views"]["status"], "ZERO_BASELINE")
        self.assertIsNone(result["metrics"]["views"]["percentage_change"])
        self.assertEqual(result["metrics"]["views"]["absolute_change"], "5")

    def test_weighted_average_duration_has_explicit_zero_denominator_status(self):
        previous = snapshot("2026-10-01", "2026-10-01", [["2026-10-01", 0, 0.0, 0.0, 0]])
        current = snapshot("2026-10-02", "2026-10-02", [["2026-10-02", 5, 1.0, 12.0, 1]])
        result = compare_analytics_periods(current, previous)
        metric = result["metrics"]["averageViewDuration"]
        self.assertEqual(metric["status"], "ZERO_DENOMINATOR")
        self.assertIsNone(metric["previous_value"])
        self.assertIsNone(metric["percentage_change"])

    def test_no_data_is_not_converted_to_zero(self):
        previous = snapshot("2026-10-01", "2026-10-01", None)
        current = snapshot("2026-10-02", "2026-10-02", [["2026-10-02", 5, 1.0, 12.0, 1]])
        result = compare_analytics_periods(current, previous)
        self.assertEqual(result["previous_period"]["data_status"], "NO_DATA")
        self.assertIsNone(result["metrics"]["views"]["previous_value"])
        self.assertEqual(result["metrics"]["views"]["status"], "INSUFFICIENT_DATA")
        self.assertIsNone(result["metrics"]["views"]["absolute_change"])

    def test_rejects_different_channel_or_metric_scope(self):
        current = snapshot("2026-10-08", "2026-10-14", [["2026-10-08", 5, 1.0, 12.0, 1]])
        previous = snapshot("2026-10-01", "2026-10-07", [["2026-10-01", 5]],
                            metrics="views")
        with self.assertRaisesRegex(YouTubeAnalyticsInsightError, "identical channel"):
            compare_analytics_periods(current, previous)

    def test_rejects_unequal_or_overlapping_periods(self):
        previous = snapshot("2026-10-01", "2026-10-06", [["2026-10-01", 5, 1.0, 12.0, 1]])
        current = snapshot("2026-10-08", "2026-10-14", [["2026-10-08", 6, 1.2, 12.0, 1]])
        with self.assertRaisesRegex(YouTubeAnalyticsInsightError, "equal inclusive"):
            compare_analytics_periods(current, previous)
        overlapping = snapshot("2026-10-06", "2026-10-12", [["2026-10-06", 6, 1.2, 12.0, 1]])
        with self.assertRaisesRegex(YouTubeAnalyticsInsightError, "must follow"):
            compare_analytics_periods(overlapping, previous)

    def test_rejects_tampered_snapshot_before_comparison(self):
        previous = snapshot("2026-10-01", "2026-10-07", [["2026-10-01", 5, 1.0, 12.0, 1]])
        current = snapshot("2026-10-08", "2026-10-14", [["2026-10-08", 6, 1.2, 12.0, 1]])
        current["response"]["rows"][0][1] = 900
        with self.assertRaisesRegex(YouTubeAnalyticsInsightError, "unverified snapshot"):
            compare_analytics_periods(current, previous)

    def test_comparison_digest_detects_tampering(self):
        previous = snapshot("2026-10-01", "2026-10-01", [["2026-10-01", 5, 1.0, 12.0, 1]])
        current = snapshot("2026-10-02", "2026-10-02", [["2026-10-02", 6, 1.2, 12.0, 1]])
        result = compare_analytics_periods(current, previous)
        altered = deepcopy(result)
        altered["metrics"]["views"]["current_value"] = "999"
        with self.assertRaisesRegex(YouTubeAnalyticsInsightError, "digest does not match"):
            verify_analytics_period_comparison(altered)

    def test_rejects_negative_analytics_metric_values(self):
        previous = snapshot("2026-10-01", "2026-10-01", [["2026-10-01", -1, 1.0, 12.0, 1]])
        current = snapshot("2026-10-02", "2026-10-02", [["2026-10-02", 6, 1.2, 12.0, 1]])
        with self.assertRaisesRegex(YouTubeAnalyticsInsightError, "is negative"):
            compare_analytics_periods(current, previous)

    def test_rejects_boolean_and_fractional_integer_metric_values(self):
        for invalid in (True, 1.5):
            with self.subTest(invalid=invalid):
                previous = snapshot("2026-10-01", "2026-10-01", [["2026-10-01", invalid, 1.0, 12.0, 1]])
                current = snapshot("2026-10-02", "2026-10-02", [["2026-10-02", 6, 1.2, 12.0, 1]])
                with self.assertRaises(YouTubeAnalyticsInsightError):
                    compare_analytics_periods(current, previous)


if __name__ == "__main__":
    unittest.main()
