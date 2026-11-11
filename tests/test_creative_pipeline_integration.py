import unittest
from datetime import date

from rhemascript.capabilities.specialists import assess_specialist
from rhemascript.capabilities.tool_registry import assess_tool_preflight

class CreativeProductionPipelineTests(unittest.TestCase):
    def test_narration_to_tool_preflight_to_qc_and_failure_learning(self):
        narration=[{"segment_id":"N1","text":"Look beyond the storm and pray.","start_seconds":0.0,"end_seconds":4.0}]

        creative=assess_specialist("CAP-05",{
            "approved_narration_segments":narration,
            "human_experience_map":[{"segment_id":"N1","human_tension":"fear under pressure",
                "emotional_intention":"steadiness","audience_response":"reflection",
                "visual_metaphor":"a narrow warm light through abstract rain",
                "biblical_boundary":"symbolic metaphor, not a literal biblical event"}],
            "beats":[{"beat_id":"B1","purpose":"communicate a shift in focus",
                "narration_segment_ids":["N1"],"shot_type":"A_ROLL",
                "subject_action":"a person turns toward a warm light",
                "visual_concept":"abstract rain gives way to a clear path"}],
            "narrative_constraints":{"style_lock":"approved","source_integrity":"mandatory"},
            "target_duration_seconds":4,
        })
        self.assertEqual(creative["simulation_status"],"STRUCTURE_VALID_FOR_EDITORIAL_REVIEW")

        production=assess_specialist("CAP-08",{
            "approved_narration_segments":narration,
            "shot_plan":[{"shot_id":"S1","duration_seconds":4,"purpose":"visualise a shift in focus",
                "visual_action":"abstract rain parts around a warm light","shot_type":"A_ROLL",
                "subject_action":"a person turns toward a warm light","narration_segment_ids":["N1"],
                "aspect_ratio":"9:16","generation_required":True,"asset_reviewed":True,
                "new_generation_justification":"No existing asset communicates this visual transition",
                "selected_operation":"text_to_video","selected_model":"gemini-omni-flash-1.2",
                "generation_unit_durations":[4]}],
            "runtime_budget_seconds":4,"asset_inventory":[],
            "generation_constraints":{"min_clip_seconds":3,"max_clip_seconds":10,"target_aspect_ratio":"9:16"},
            "audio_caption_plan":{"narration_master_id":"MASTER-01",
                "caption_segments":[{"segment_id":"N1","text":narration[0]["text"],"start_seconds":0,"end_seconds":4}],
                "audio_cues":[]},
        })
        self.assertEqual(production["feasibility"],"STRUCTURALLY_FEASIBLE_FOR_HUMAN_REVIEW")

        checks={"style_match":True,"subject_match":True,"environment_match":True,
            "screen_direction_match":True,"lighting_match":True,"palette_match":True,"camera_axis_match":True}
        visual=assess_specialist("CAP-07",{
            "visual_reference_set":[{"reference_id":"STYLE-01","version":"1.0","description":"Approved visual bible reference"}],
            "shot_observations":[{"shot_id":"S1","sequence_id":"SEQ-01","reference_id":"STYLE-01",
                "subject_identity_id":"SUBJECT-01","style_profile_id":"STYLE-01",
                "continuity_observations":checks,"review_basis":"HUMAN_FRAME_REVIEW"}],
        })
        self.assertEqual(visual["continuity_status"],"STRUCTURALLY_CONSISTENT_FOR_HUMAN_REVIEW")

        tool=assess_tool_preflight({
            "target_platform":"YouTube Shorts",
            "generation_request":{"provider":"google","interface":"flow_web","model":"gemini-omni-flash-1.2",
                "operation":"text_to_video","duration_seconds":4,"aspect_ratio":"9:16","resolution":"720p",
                "plan_tier":"NONE","region_status":"USER_CONFIRMED_AVAILABLE",
                "ui_settings_confirmed":True,"selected_model_confirmed":True},
            "verified_tool_evidence":[{"provider":"google","interface":"flow_web",
                "model":"gemini-omni-flash-1.2","operation":"text_to_video",
                "knowledge_state":"VERIFIED_CURRENT","checked_at":"2026-11-11",
                "source_url":"https://support.google.com/flow/answer/16352836"}],
        },as_of=date(2026,11,11))
        self.assertEqual(tool["preflight_status"],"COMPATIBLE_FOR_HUMAN_REVIEW")
        self.assertFalse(tool["generation_authorised"])

        quality={key:95 for key in ("biblical_integrity","script_narration","narrative","visual","audio",
            "technical","rights_provenance","security_compliance","audience_suitability")}
        qc=assess_specialist("CAP-11",{"quality_dimensions":quality,"hard_stop_findings":[],
            "qc_evidence":{"approved_narration_text":narration[0]["text"],
                "final_transcript_text":narration[0]["text"],"transcript_source":"HUMAN_TRANSCRIPT",
                "biblical_integrity_status":"PASS","source_integrity_status":"PASS","rights_status":"CLEARED",
                "platform_compliance_status":"PASS","visual_alignment_findings":[{"segment_id":"N1","alignment_status":"PASS"}],
                "audio_visual_findings":[],"caption_findings":[{"segment_id":"N1","text_match":True,"timing_match":True,"safe_area_pass":True}],
                "technical_export":{"expected_aspect_ratio":"9:16","actual_aspect_ratio":"9:16",
                    "expected_runtime_seconds":4,"actual_runtime_seconds":4,
                    "expected_resolution":"1080x1920","actual_resolution":"1080x1920",
                    "expected_fps":30,"actual_fps":30}}})
        self.assertEqual(qc["release_recommendation"],"ELIGIBLE_FOR_HUMAN_ACCEPTANCE")

        failure=assess_specialist("CAP-14",{
            "failure_record":{"category":"TOOL","severity":"LOW"},
            "reproduction_or_observation":"A generated take had a one-frame visual flicker.",
            "diagnostic_evidence":{"stage":"generation","model_or_tool":"Gemini Omni Flash 1.2",
                "tool_version":"1.2","prompt_version":"MASTER-PROMPT-V1",
                "expected_behavior":"Stable painterly texture","observed_behavior":"One-frame flicker",
                "root_cause_status":"NOT_ESTABLISHED","corrective_action":"Review source frames and prompt",
                "reproduction_steps":["Review exported clip frame by frame"],
                "evidence_references":["asset:clip-01"],"security_or_rights_risk":False,
                "retest_status":"NOT_RUN"},
        })
        self.assertFalse(failure["automatic_retry_authorised"])
        self.assertEqual(failure["root_cause_status"],"NOT_ESTABLISHED")

if __name__=="__main__":
    unittest.main()
