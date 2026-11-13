import unittest
from copy import deepcopy
from datetime import datetime, timezone, timedelta

from rhemascript.integrations.youtube_analytics_evidence import (
    YouTubeAnalyticsEvidenceError,
    build_analytics_evidence_snapshot,
    verify_analytics_evidence_snapshot,
)


PARAMS = {
    "ids": "channel==MINE",
    "startDate": "2026-11-01",
    "endDate": "2026-11-12",
    "metrics": "views",
    "dimensions": "day",
}
REPORT = {
    "kind": "youtubeAnalytics#resultTable",
    "columnHeaders": [
        {"name": "day", "dataType": "STRING", "columnType": "DIMENSION"},
        {"name": "views", "dataType": "INTEGER", "columnType": "METRIC"},
    ],
    "rows": [["2026-11-10", 17], ["2026-11-11", 23]],
}
RETRIEVED = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


class YouTubeAnalyticsEvidenceTests(unittest.TestCase):
    def build(self, **overrides):
        args = {
            "params": deepcopy(PARAMS),
            "report": deepcopy(REPORT),
            "retrieved_at": RETRIEVED,
        }
        args.update(overrides)
        return build_analytics_evidence_snapshot(**args)

    def test_snapshot_binds_exact_query_response_and_timestamp(self):
        snapshot = self.build()
        self.assertTrue(verify_analytics_evidence_snapshot(snapshot))
        self.assertEqual(snapshot["query"], PARAMS)
        self.assertEqual(snapshot["response"], REPORT)
        self.assertEqual(snapshot["retrieved_at"], "2026-11-13T12:00:00Z")
        self.assertEqual(snapshot["row_count"], 2)
        self.assertFalse(snapshot["no_data"])
        self.assertEqual(len(snapshot["response_sha256"]), 64)
        self.assertEqual(len(snapshot["snapshot_sha256"]), 64)

    def test_retrieval_timestamp_is_normalized_to_utc(self):
        local = datetime(2026, 11, 13, 17, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        snapshot = self.build(retrieved_at=local)
        self.assertEqual(snapshot["retrieved_at"], "2026-11-13T12:00:00Z")
        self.assertTrue(verify_analytics_evidence_snapshot(snapshot))

    def test_missing_rows_are_preserved_as_no_data_not_zero(self):
        report = deepcopy(REPORT)
        report.pop("rows")
        snapshot = self.build(report=report)
        self.assertEqual(snapshot["row_count"], 0)
        self.assertTrue(snapshot["no_data"])
        self.assertNotIn("rows", snapshot["response"])
        self.assertTrue(verify_analytics_evidence_snapshot(snapshot))

    def test_rejects_naive_retrieval_timestamp(self):
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "timezone-aware"):
            self.build(retrieved_at=datetime(2026, 11, 13, 12, 0))

    def test_rejects_invalid_report_before_snapshot_creation(self):
        report = deepcopy(REPORT)
        report["rows"][0].append("unexpected")
        with self.assertRaises(YouTubeAnalyticsEvidenceError):
            self.build(report=report)

    def test_rejects_invalid_query_before_snapshot_creation(self):
        params = deepcopy(PARAMS)
        params["ids"] = "channel==OTHER"
        with self.assertRaises(YouTubeAnalyticsEvidenceError):
            self.build(params=params)

    def test_verifier_detects_response_tampering(self):
        snapshot = self.build()
        altered = deepcopy(snapshot)
        altered["response"]["rows"][0][1] = 999
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "response digest"):
            verify_analytics_evidence_snapshot(altered)

    def test_verifier_detects_query_or_timestamp_tampering(self):
        for field, value in (("query", {**PARAMS, "startDate": "2026-11-02"}),
                             ("retrieved_at", "2026-11-13T13:00:00Z")):
            with self.subTest(field=field):
                altered = self.build()
                altered[field] = value
                with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "snapshot digest"):
                    verify_analytics_evidence_snapshot(altered)

    def test_verifier_rejects_unsupported_fields_and_wrong_row_metadata(self):
        snapshot = self.build()
        altered = deepcopy(snapshot)
        altered["recommendation"] = "publish more"
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "unsupported fields"):
            verify_analytics_evidence_snapshot(altered)
        altered = self.build()
        altered["row_count"] = 0
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "row metadata"):
            verify_analytics_evidence_snapshot(altered)
        altered = self.build()
        altered["row_count"] = True
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "row metadata"):
            verify_analytics_evidence_snapshot(altered)
        altered = self.build()
        altered["no_data"] = 0
        with self.assertRaisesRegex(YouTubeAnalyticsEvidenceError, "row metadata"):
            verify_analytics_evidence_snapshot(altered)

    def test_non_finite_json_values_are_rejected(self):
        report = deepcopy(REPORT)
        report["rows"][0][1] = float("nan")
        with self.assertRaises(YouTubeAnalyticsEvidenceError):
            self.build(report=report)


if __name__ == "__main__":
    unittest.main()
