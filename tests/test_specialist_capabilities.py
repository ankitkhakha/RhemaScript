import unittest
from rhemascript.capabilities.specialists import assess_specialist, SpecialistInputError, SPECIALISTS
from rhemascript.capabilities import CapabilityEngine, CapabilityError
from tests.test_runtime_integration import RECORD

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
        result=assess_specialist("CAP-11",{"quality_dimensions":scores,"hard_stop_findings":["RIGHTS_UNCLEARED"]})
        self.assertEqual(result["release_recommendation"],"BLOCKED_BY_HARD_STOP")

    def test_script_mapping_reports_unmapped_story_element(self):
        result=assess_specialist("CAP-03",{"script_elements":[{"element_id":"S1"}],"source_mapping":[]})
        self.assertEqual(result["unmapped_elements"],["S1"])

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
