import unittest
from datetime import datetime, timezone

from rhemascript.integrations.youtube_analytics_evidence import build_analytics_evidence_snapshot
from rhemascript.integrations.youtube_analytics_coverage import (
    YouTubeAnalyticsCoverageError,
    diagnose_daily_coverage,
    verify_daily_coverage_diagnostic,
)


def make_snapshot(start, end, rows, *, dimensions="day"):
    names = dimensions.split(",")
    headers = [
        {"name": name, "dataType": "STRING", "columnType": "DIMENSION"}
        for name in names
    ]
    headers.append({"name": "views", "dataType": "INTEGER", "columnType": "METRIC"})
    report = {"kind": "youtubeAnalytics#resultTable", "columnHeaders": headers}
    if rows is not None:
        report["rows"] = rows
    return build_analytics_evidence_snapshot(
        params={
            "ids": "channel==MINE", "startDate": start, "endDate": end,
            "metrics": "views", "dimensions": dimensions,
        },
        report=report,
        retrieved_at=datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc),
    )


class YouTubeAnalyticsCoverageTests(unittest.TestCase):
    def test_reports_leading_internal_and_trailing_gaps_without_imputation(self):
        source = make_snapshot("2026-11-01", "2026-11-05", [
            ["2026-11-01", 5],
            ["2026-11-02", 8],
            ["2026-11-04", 3],
        ])
        diagnostic = diagnose_daily_coverage(source)
        self.assertEqual(diagnostic["expected_days"], 5)
        self.assertEqual(diagnostic["distinct_returned_days"], 3)
        self.assertEqual(diagnostic["missing_dates"], ["2026-11-03", "2026-11-05"])
        self.assertEqual(diagnostic["internal_gap_dates"], ["2026-11-03"])
        self.assertEqual(diagnostic["trailing_gap_dates"], ["2026-11-05"])
        self.assertEqual(diagnostic["coverage_ratio"], "0.600000")
        self.assertTrue(verify_daily_coverage_diagnostic(diagnostic, source))

    def test_multidimension_rows_count_distinct_days_not_total_rows(self):
        source = make_snapshot("2026-11-01", "2026-11-02", [
            ["US", "2026-11-01", 5],
            ["IN", "2026-11-01", 7],
            ["US", "2026-11-02", 3],
        ], dimensions="country,day")
        diagnostic = diagnose_daily_coverage(source)
        self.assertEqual(diagnostic["returned_rows"], 3)
        self.assertEqual(diagnostic["distinct_returned_days"], 2)
        self.assertEqual(diagnostic["missing_dates"], [])

    def test_no_rows_means_unknown_dates_not_zero_activity(self):
        source = make_snapshot("2026-11-01", "2026-11-03", None)
        diagnostic = diagnose_daily_coverage(source)
        self.assertEqual(diagnostic["coverage_ratio"], "0.000000")
        self.assertEqual(diagnostic["missing_dates"], [
            "2026-11-01", "2026-11-02", "2026-11-03",
        ])

    def test_rejects_reports_without_day_dimension(self):
        source = make_snapshot("2026-11-01", "2026-11-02", [["US", 5]], dimensions="country")
        with self.assertRaisesRegex(YouTubeAnalyticsCoverageError, "requires the day dimension"):
            diagnose_daily_coverage(source)

    def test_rejects_day_outside_query_range(self):
        source = make_snapshot("2026-11-01", "2026-11-02", [["2026-11-03", 5]])
        with self.assertRaisesRegex(YouTubeAnalyticsCoverageError, "outside the requested range"):
            diagnose_daily_coverage(source)

    def test_verifier_rejects_changed_diagnostic(self):
        source = make_snapshot("2026-11-01", "2026-11-02", [["2026-11-01", 5]])
        diagnostic = diagnose_daily_coverage(source)
        diagnostic["coverage_ratio"] = "1.000000"
        with self.assertRaisesRegex(YouTubeAnalyticsCoverageError, "does not match"):
            verify_daily_coverage_diagnostic(diagnostic, source)


if __name__ == "__main__":
    unittest.main()
