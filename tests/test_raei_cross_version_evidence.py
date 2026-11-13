import json
import unittest

from test_raei_finding_lifecycle import RAEIFindingLifecycleTests
from raei.finding_lifecycle import RAEIFindingLifecycleError, record_finding_research
from rhemascript.evidence.artifact_verification import verify_artifact


class CrossVersionEvidenceSubstitutionTests(unittest.TestCase):
    def test_research_report_cannot_claim_another_evidence_version(self):
        fixture = RAEIFindingLifecycleTests("test_report_bytes_must_match_verified_evidence")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)

        report = fixture._research_report()
        report["evidence_version"] = "2.0"
        raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        path = fixture.evidence_root / "research-cross-version.json"
        path.write_bytes(raw)
        verified_v1 = verify_artifact(
            fixture.evidence_root, path.name,
            evidence_id=report["evidence_id"], version="1.0",
        )
        credential = fixture._credential(
            "FINDING_RESEARCH", verified_v1,
            subject_id="subject-cross-version-researcher",
            actor_id="actor-cross-version-researcher",
            session_id="session-cross-version-researcher",
        )
        before = len(fixture.registry.list_activity_events())

        with self.assertRaisesRegex(
            RAEIFindingLifecycleError, "exact verified evidence version"
        ):
            record_finding_research(
                fixture.registry, fixture.verifier, credential,
                finding_id=fixture.finding_id,
                finding_version=fixture.finding_version,
                project_id=fixture.project_id,
                project_version=fixture.project_version,
                request_id=f"request-FINDING_RESEARCH-{fixture.finding_id}",
                evidence_root=str(fixture.evidence_root),
                artifact_bytes=raw,
                evidence=verified_v1,
            )

        self.assertEqual(len(fixture.registry.list_activity_events()), before)
        self.assertTrue(fixture.registry.verify())


if __name__ == "__main__":
    unittest.main()
