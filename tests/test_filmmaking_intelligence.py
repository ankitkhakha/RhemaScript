import unittest

from rhemascript.capabilities.specialists import assess_specialist

def narration():
    return [
        {"segment_id":"N1","text":"When the storms hit, where do your eyes lock?","start_seconds":0.0,"end_seconds":4.0},
        {"segment_id":"N2","text":"Shift your gaze and pray.","start_seconds":4.0,"end_seconds":7.0},
    ]

def human_map():
    return [
        {"segment_id":"N1","human_tension":"overwhelmed by pressure","emotional_intention":"unease","audience_response":"recognition","visual_metaphor":"a room filling with abstract water","biblical_boundary":"metaphor, not a biblical event"},
        {"segment_id":"N2","human_tension":"seeking direction under pressure","emotional_intention":"hope","audience_response":"reflection","visual_metaphor":"a narrow path of warm light","biblical_boundary":"symbolic response, not a promise of instant relief"},
    ]

def creative_evidence():
    return {
        "approved_narration_segments":narration(),
        "human_experience_map":human_map(),
        "beats":[
            {"beat_id":"B1","purpose":"establish pressure","narration_segment_ids":["N1"],"shot_type":"A_ROLL","subject_action":"a person pauses at a desk","visual_concept":"the room begins to flood symbolically"},
            {"beat_id":"B2","purpose":"communicate a shift in attention","narration_segment_ids":["N2"],"shot_type":"B_ROLL","broll_purpose":"show a visual metaphor for a change in focus","visual_concept":"warm light reveals a path"},
        ],
        "narrative_constraints":{"approved_style":"watercolor-and-pencil","no_unverified_biblical_claims":True},
        "target_duration_seconds":7,
    }

def production_evidence():
    approved=narration()
    return {
        "approved_narration_segments":[approved[0]],
        "shot_plan":[{
            "shot_id":"S1","duration_seconds":4.0,"purpose":"show pressure building",
            "visual_action":"abstract water rises around a desk","shot_type":"A_ROLL",
            "subject_action":"a person pauses at the desk","narration_segment_ids":["N1"],
            "aspect_ratio":"9:16","generation_required":True,"asset_reviewed":True,
            "new_generation_justification":"No existing asset communicates the required transformation",
            "selected_operation":"text_to_video","selected_model":"gemini-omni-flash-1.2",
            "generation_unit_durations":[4.0],
        }],
        "runtime_budget_seconds":5,
        "asset_inventory":[],
        "generation_constraints":{"min_clip_seconds":3,"max_clip_seconds":10,"target_aspect_ratio":"9:16"},
        "audio_caption_plan":{
            "narration_master_id":"NARRATION-MASTER-01",
            "caption_segments":[{"segment_id":"N1","text":approved[0]["text"],"start_seconds":0.0,"end_seconds":4.0}],
            "audio_cues":[{"start_seconds":0.0,"end_seconds":4.0,"overlaps_narration":True,"duck_under_narration":True}],
        },
    }

class CreativeStoryIntelligenceTests(unittest.TestCase):
    def test_cap05_maps_narration_to_human_experience_and_shot_beats(self):
        result=assess_specialist("CAP-05",creative_evidence())
        self.assertEqual(result["simulation_status"],"STRUCTURE_VALID_FOR_EDITORIAL_REVIEW")
        self.assertEqual(result["narration_segments_without_visual_coverage"],[])
        self.assertEqual(result["unmapped_human_experience_segments"],[])

    def test_cap05_flags_uncovered_narration_and_missing_broll_reason(self):
        evidence=creative_evidence()
        evidence["beats"][1]["narration_segment_ids"]=[]
        evidence["beats"][1].pop("broll_purpose")
        result=assess_specialist("CAP-05",evidence)
        self.assertEqual(result["simulation_status"],"STRUCTURAL_ISSUES")
        self.assertIn("N2",result["narration_segments_without_visual_coverage"])
        self.assertIn("BROLL_PURPOSE_MISSING",result["beat_findings"][1]["flags"])

    def test_cap05_requires_human_experience_boundary(self):
        evidence=creative_evidence()
        evidence["human_experience_map"][0].pop("biblical_boundary")
        result=assess_specialist("CAP-05",evidence)
        self.assertIn("MISSING_BIBLICAL_BOUNDARY",result["human_experience_map_findings"][0]["flags"])

class ProductionFeasibilityTests(unittest.TestCase):
    def test_cap08_accepts_narration_caption_and_generation_plan(self):
        result=assess_specialist("CAP-08",production_evidence())
        self.assertEqual(result["feasibility"],"STRUCTURALLY_FEASIBLE_FOR_HUMAN_REVIEW")
        self.assertEqual(result["missing_caption_segments"],[])
        self.assertEqual(result["caption_text_mismatches"],[])
        self.assertEqual(result["asset_first_reviewed_shots"],1)

    def test_cap08_flags_caption_paraphrase_and_timing_drift(self):
        evidence=production_evidence()
        evidence["audio_caption_plan"]["caption_segments"][0]["text"]="A different sentence"
        evidence["audio_caption_plan"]["caption_segments"][0]["end_seconds"]=5.5
        result=assess_specialist("CAP-08",evidence)
        self.assertIn("N1",result["caption_text_mismatches"])
        self.assertIn("N1",result["caption_timing_mismatches"])
        self.assertEqual(result["feasibility"],"GAPS_FOUND")

    def test_cap08_blocks_unreviewed_asset_generation_and_unsupported_unit(self):
        evidence=production_evidence()
        shot=evidence["shot_plan"][0]
        shot["asset_reviewed"]=False
        shot["generation_unit_durations"]=[11.0]
        result=assess_specialist("CAP-08",evidence)
        self.assertIn("ASSET_FIRST_REVIEW_MISSING",result["shot_findings"][0]["flags"])
        self.assertIn("GENERATION_UNIT_DURATION_UNSUPPORTED",result["shot_findings"][0]["flags"])

    def test_cap08_flags_audio_masking_risk(self):
        evidence=production_evidence()
        evidence["audio_caption_plan"]["audio_cues"][0]["duck_under_narration"]=False
        result=assess_specialist("CAP-08",evidence)
        self.assertEqual(result["audio_findings"][0]["flag"],"AUDIO_MASKING_RISK")

    def test_cap08_flags_missing_caption_and_ratio_mismatch(self):
        evidence=production_evidence()
        evidence["audio_caption_plan"]["caption_segments"]=[]
        evidence["shot_plan"][0]["aspect_ratio"]="16:9"
        result=assess_specialist("CAP-08",evidence)
        self.assertEqual(result["missing_caption_segments"],["N1"])
        self.assertIn("SHOT_ASPECT_RATIO_MISMATCH",result["shot_findings"][0]["flags"])

if __name__=="__main__":
    unittest.main()
