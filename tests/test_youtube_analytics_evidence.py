import unittest

from rhemascript.capabilities.specialists import assess_specialist
from rhemascript.integrations.youtube_analytics_evidence import (
    YouTubeAnalyticsEvidenceError, build_cap15_performance_evidence,
)


class YouTubeAnalyticsEvidenceTests(unittest.TestCase):
    def report(self):
        return {
            "columnHeaders": [
                {"name": "day", "columnType": "DIMENSION"},
                {"name": "views", "columnType": "METRIC"},
                {"name": "averageViewDuration", "columnType": "METRIC"},
            ],
            "rows": [["2026-11-11", 125, 18.5], ["2026-11-12", "80", "21.0"]],
        }

    def test_report_is_linked_to_explicit_video_and_production_version(self):
        evidence = build_cap15_performance_evidence(
            self.report(), video_id="yt-video-1", production_version="RS-001-v2",
            evidence_reference="evidence://analytics/RS-001-v2/report-1",
        )
        result = assess_specialist("CAP-15", evidence)
        self.assertEqual(result["linked_production_version"], "RS-001-v2")
        self.assertEqual(result["matching_version_observations"], 2)
        self.assertFalse(evidence["causal_claims_allowed"])
        self.assertEqual(evidence["performance_observations"][0]["metrics"]["views"], 125.0)

    def test_rejects_report_rows_that_do_not_match_headers(self):
        report = self.report()
        report["rows"] = [["2026-11-11", 125]]
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "does not match"):
            build_cap15_performance_evidence(report, video_id="v1",
                production_version="p1", evidence_reference="e1")

    def test_rejects_non_finite_or_negative_metrics(self):
        for value in (float("nan"), float("inf"), -1):
            report = self.report()
            report["rows"] = [["2026-11-11", value, 10]]
            with self.subTest(value=value):
                with self.assertRaises(YouTubeAnalyticsEvidenceError):
                    build_cap15_performance_evidence(report, video_id="v1",
                        production_version="p1", evidence_reference="e1")

    def test_rejects_missing_explicit_production_linkage(self):
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "production_version"):
            build_cap15_performance_evidence(self.report(), video_id="v1",
                production_version=" ", evidence_reference="e1")

    def test_rejects_duplicate_or_malformed_headers(self):
        report = self.report()
        report["columnHeaders"].append({"name": "views", "columnType": "METRIC"})
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "invalid or duplicated"):
            build_cap15_performance_evidence(report, video_id="v1",
                production_version="p1", evidence_reference="e1")


if __name__ == "__main__":
    unittest.main()
