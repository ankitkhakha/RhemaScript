import math
import unittest

from rhemascript.capabilities.specialists import assess_specialist, SpecialistInputError


class SpecialistEvidenceHardeningTests(unittest.TestCase):
    def test_cap04_missing_eligibility_gates_cannot_pass(self):
        evidence = {
            "dimension_scores": {
                "biblical_relevance": 80, "audience_relevance": 80,
                "content_value": 80, "discovery_potential": 80,
                "differentiation": 80, "narrative_suitability": 80,
                "production_feasibility": 80, "strategic_alignment": 80,
            },
            "eligibility_gates": {},
        }
        with self.assertRaisesRegex(SpecialistInputError, "eligibility_gates"):
            assess_specialist("CAP-04", evidence)

    def _cap08_evidence(self, budget=120, shot_duration=120):
        return {
            "shot_plan": [{
                "shot_id": "SHOT-01",
                "duration_seconds": shot_duration,
                "shot_type": "A_ROLL",
                "purpose": "Establish the scene",
                "visual_action": "The subject looks toward the window",
                "subject_action": "Looks toward the window",
                "aspect_ratio": "9:16",
                "generation_required": False,
                "narration_segment_ids": ["NARR-01"],
            }],
            "runtime_budget_seconds": budget,
            "asset_inventory": [],
            "approved_narration_segments": [{
                "segment_id": "NARR-01",
                "text": "An approved narration segment.",
                "start_seconds": 0,
                "end_seconds": shot_duration,
            }],
            "audio_caption_plan": {
                "narration_master_id": "NARRATION-MASTER-01",
                "caption_segments": [{
                    "segment_id": "NARR-01",
                    "text": "An approved narration segment.",
                    "start_seconds": 0,
                    "end_seconds": shot_duration,
                }],
                "audio_cues": [],
            },
            "generation_constraints": {
                "max_clip_seconds": 10,
                "min_clip_seconds": 0,
                "target_aspect_ratio": "9:16",
            },
        }

    def test_cap08_accepts_valid_runtime_budgets_above_100_seconds(self):
        result = assess_specialist("CAP-08", self._cap08_evidence())
        self.assertEqual(result["runtime_budget_seconds"], 120.0)
        self.assertEqual(result["planned_runtime_seconds"], 120.0)
        self.assertEqual(result["feasibility"], "STRUCTURALLY_FEASIBLE_FOR_HUMAN_REVIEW")

    def test_cap08_rejects_non_finite_runtime_budget(self):
        with self.assertRaisesRegex(SpecialistInputError, "runtime_budget_seconds"):
            assess_specialist("CAP-08", self._cap08_evidence(budget=math.nan))

    def test_cap08_rejects_non_finite_shot_duration(self):
        evidence = self._cap08_evidence(shot_duration=120)
        evidence["shot_plan"][0]["duration_seconds"] = math.inf
        with self.assertRaisesRegex(SpecialistInputError, "duration_seconds"):
            assess_specialist("CAP-08", evidence)

    def test_cap08_rejects_non_finite_narration_timing(self):
        evidence = self._cap08_evidence()
        evidence["approved_narration_segments"][0]["start_seconds"] = math.nan
        with self.assertRaisesRegex(SpecialistInputError, "approved_narration_segments"):
            assess_specialist("CAP-08", evidence)

    def test_cap08_flags_non_finite_caption_timing(self):
        evidence = self._cap08_evidence()
        evidence["audio_caption_plan"]["caption_segments"][0]["start_seconds"] = math.nan
        result = assess_specialist("CAP-08", evidence)
        self.assertEqual(result["caption_timing_mismatches"], ["NARR-01"])
        self.assertEqual(result["feasibility"], "GAPS_FOUND")

    def test_cap08_malformed_generation_units_do_not_crash_during_sum(self):
        evidence = self._cap08_evidence(budget=10, shot_duration=10)
        shot = evidence["shot_plan"][0]
        shot.update({
            "generation_required": True,
            "asset_reviewed": True,
            "new_generation_justification": "Synthetic regression fixture",
            "selected_operation": "SYNTHETIC_TEST",
            "selected_model": "SYNTHETIC_MODEL",
            "generation_unit_durations": ["not-a-number"],
        })
        result = assess_specialist("CAP-08", evidence)
        self.assertIn("GENERATION_UNIT_DURATION_UNSUPPORTED", result["shot_findings"][0]["flags"])
        self.assertNotIn("GENERATION_UNITS_DO_NOT_MATCH_SHOT_DURATION", result["shot_findings"][0]["flags"])

    def test_cap03_malformed_script_element_fails_with_domain_error(self):
        with self.assertRaisesRegex(SpecialistInputError, "script_elements"):
            assess_specialist("CAP-03", {
                "script_elements": ["not-an-object"],
                "source_mapping": [],
            })

    def test_cap13_malformed_provenance_entry_is_reported_not_crashed(self):
        result = assess_specialist("CAP-13", {
            "provenance_chain": ["not-an-object"],
            "rights_basis": {"basis_reference": "synthetic-evidence"},
        })
        self.assertEqual(result["clearance_status"], "NOT_CLEARED")
        self.assertEqual(result["provenance_gaps"][0]["error"], "ENTRY_NOT_OBJECT")


if __name__ == "__main__":
    unittest.main()
