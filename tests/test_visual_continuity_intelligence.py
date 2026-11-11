import unittest

from rhemascript.capabilities.specialists import assess_specialist

def visual_evidence():
    checks={
        "style_match":True,"subject_match":True,"environment_match":True,
        "screen_direction_match":True,"lighting_match":True,"palette_match":True,
        "camera_axis_match":True,
    }
    return {
        "visual_reference_set":[
            {"reference_id":"REF-STYLE","version":"1.0","description":"Approved painterly watercolor-and-pencil style reference","reference_type":"STYLE"},
            {"reference_id":"REF-SUBJECT","version":"1.0","description":"Approved anonymous silhouette reference","reference_type":"SUBJECT"},
        ],
        "shot_observations":[
            {"shot_id":"S1","sequence_id":"SEQ-1","reference_id":"REF-STYLE",
             "subject_identity_id":"SUBJECT-A","style_profile_id":"STYLE-A",
             "continuity_observations":dict(checks),"review_basis":"HUMAN_FRAME_REVIEW"},
            {"shot_id":"S2","sequence_id":"SEQ-1","reference_id":"REF-SUBJECT",
             "subject_identity_id":"SUBJECT-A","style_profile_id":"STYLE-A",
             "continuity_observations":dict(checks),"review_basis":"HUMAN_FRAME_REVIEW"},
        ],
    }

class VisualContinuityIntelligenceTests(unittest.TestCase):
    def test_cap07_accepts_complete_supplied_continuity_observations(self):
        result=assess_specialist("CAP-07",visual_evidence())
        self.assertEqual(result["continuity_status"],"STRUCTURALLY_CONSISTENT_FOR_HUMAN_REVIEW")
        self.assertEqual(result["shots_with_continuity_flags"],0)

    def test_cap07_flags_style_and_screen_direction_mismatch(self):
        evidence=visual_evidence()
        evidence["shot_observations"][1]["continuity_observations"]["style_match"]=False
        evidence["shot_observations"][1]["continuity_observations"]["screen_direction_match"]=False
        result=assess_specialist("CAP-07",evidence)
        flags=result["shot_findings"][1]["flags"]
        self.assertIn("STYLE_MATCH_MISMATCH",flags)
        self.assertIn("SCREEN_DIRECTION_MATCH_MISMATCH",flags)
        self.assertEqual(result["continuity_status"],"REVIEW_REQUIRED")

    def test_cap07_flags_unexplained_subject_and_style_changes(self):
        evidence=visual_evidence()
        evidence["shot_observations"][1]["subject_identity_id"]="SUBJECT-B"
        evidence["shot_observations"][1]["style_profile_id"]="STYLE-B"
        result=assess_specialist("CAP-07",evidence)
        flags=result["shot_findings"][1]["flags"]
        self.assertIn("UNEXPLAINED_SUBJECT_IDENTITY_CHANGE",flags)
        self.assertIn("UNEXPLAINED_STYLE_PROFILE_CHANGE",flags)

    def test_cap07_requires_reference_and_explicit_review_basis(self):
        evidence=visual_evidence()
        evidence["shot_observations"][0]["reference_id"]="MISSING"
        evidence["shot_observations"][0]["review_basis"]="MODEL_GUESS"
        result=assess_specialist("CAP-07",evidence)
        flags=result["shot_findings"][0]["flags"]
        self.assertIn("REFERENCE_NOT_FOUND",flags)
        self.assertIn("VISUAL_REVIEW_BASIS_NOT_ESTABLISHED",flags)

    def test_cap07_never_claims_it_inspected_actual_pixels(self):
        result=assess_specialist("CAP-07",visual_evidence())
        self.assertIn("no pixels",result["visual_assessment_boundary"])

if __name__=="__main__":
    unittest.main()
