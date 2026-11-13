import unittest
from rhemascript.capabilities.specialists import assess_specialist, SpecialistInputError, SPECIALISTS
from rhemascript.capabilities import CapabilityEngine, CapabilityError
RECORD={"record_id":"RSN-SYN-001","record_type":"SYNTHETIC_PROJECT","schema_version":"1.0","project_id":"RSN-PRJ-SYN-001","status":"DRAFT","classification":"OPERATIONAL","version":"1.0"}

class SpecialistCapabilityTests(unittest.TestCase):
    def test_all_fifteen_have_distinct_specialist_handlers(self):
        self.assertEqual(len(SPECIALISTS),15)
        self.assertEqual(set(SPECIALISTS),{f"CAP-{i:02d}" for i in range(1,16)})

    def test_content_scoring_hard_gate_overrides_score(self):
        evidence={"dimension_scores":{"biblical_relevance":100,"audience_relevance":100,"content_value":100,
        "discovery_potential":100,"differentiation":100,"narrative_suitability":100,
        "production_feasibility":100,"strategic_alignment":100},"eligibility_gates":{"script_verified":False}}
        result=assess_specialist("CAP-04",evidence)
        self.assertEqual(result["recommendation"],"INELIGIBLE")

    def test_quality_hard_stop_cannot_be_averaged_away(self):
        scores={"biblical_integrity":100,"script_narration":100,"narrative":100,"visual":100,"audio":100,
        "technical":100,"rights_provenance":100,"security_compliance":100,"audience_suitability":100}
        qc={
            "approved_narration_text":"The Lord is faithful.",
            "final_transcript_text":"The Lord is faithful.",
            "transcript_source":"HUMAN_TRANSCRIPT",
            "biblical_integrity_status":"PASS","source_integrity_status":"PASS",
            "rights_status":"CLEARED","platform_compliance_status":"PASS",
            "visual_alignment_findings":[],"audio_visual_findings":[],"caption_findings":[],
            "technical_export":{"expected_aspect_ratio":"9:16","actual_aspect_ratio":"9:16",
                "expected_runtime_seconds":30,"actual_runtime_seconds":30,
                "expected_resolution":"1080x1920","actual_resolution":"1080x1920",
                "expected_fps":30,"actual_fps":30},
        }
        result=assess_specialist("CAP-11",{"quality_dimensions":scores,"hard_stop_findings":["RIGHTS_UNCLEARED"],"qc_evidence":qc})
        self.assertEqual(result["release_recommendation"],"BLOCKED_BY_HARD_STOP")

    def test_script_mapping_reports_unmapped_story_element(self):
        result=assess_specialist("CAP-03",{"script_elements":[{"element_id":"S1"}],"source_mapping":[]})
        self.assertEqual(result["unmapped_elements"],["S1"])

    def test_script_mapping_requires_interpretation_classification(self):
        result = assess_specialist("CAP-03", {
            "script_elements": [{"element_id": "S1"}],
            "source_mapping": [{
                "element_id": "S1",
                "source_reference": "Exodus 31:1-11",
            }],
        })
        self.assertEqual(result["unclassified_mapping_indexes"], [0])
        self.assertEqual(result["integrity_status"], "GAPS_FOUND")

    def test_script_mapping_distinguishes_text_from_modern_application(self):
        result = assess_specialist("CAP-03", {
            "script_elements": [
                {"element_id": "BIBLICAL-CLAIM"},
                {"element_id": "SYSTEM-APPLICATION"},
            ],
            "source_mapping": [
                {
                    "element_id": "BIBLICAL-CLAIM",
                    "source_reference": "Exodus 31:1-11",
                    "interpretation_class": "EXPLICIT_TEXT",
                },
                {
                    "element_id": "SYSTEM-APPLICATION",
                    "source_reference": "Exodus 31:1-11",
                    "interpretation_class": "MODERN_APPLICATION",
                },
            ],
        })
        self.assertEqual(result["integrity_status"], "MAPPING_COMPLETE")
        self.assertEqual(
            [item["interpretation_class"] for item in result["mapping_classifications"]],
            ["EXPLICIT_TEXT", "MODERN_APPLICATION"],
        )
        self.assertIn("do not establish interpretive correctness", result["note"])

    def test_performance_never_claims_causation(self):
        result=assess_specialist("CAP-15",{"performance_observations":[{"production_version":"v2","views":100}],
        "linked_production_version":"v2"})
        self.assertFalse(result["causal_claims_allowed"])

    def test_missing_specialist_shape_fails_closed(self):
        with self.assertRaises(SpecialistInputError):
            assess_specialist("CAP-04",{"dimension_scores":{},"eligibility_gates":{}})

    def test_runtime_returns_specialist_assessment(self):
        evidence={"sources":[{"source_id":"S1","reference":"John 1:1","version":"HINOVBSI"}]}
        result=CapabilityEngine().execute("CAP-01",RECORD,actor_role="TEST",evidence=evidence)
        self.assertIn("specialist_assessment",result.outputs)
        self.assertEqual(result.outputs["specialist_assessment"]["source_count"],1)

if __name__=="__main__": unittest.main()
