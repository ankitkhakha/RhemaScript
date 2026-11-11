import unittest

from rhemascript.capabilities.specialists import assess_specialist

def qc_evidence():
    return {
        "approved_narration_text":"Look to the light and pray.",
        "final_transcript_text":"Look to the light and pray.",
        "transcript_source":"HUMAN_TRANSCRIPT",
        "biblical_integrity_status":"PASS",
        "source_integrity_status":"PASS",
        "rights_status":"CLEARED",
        "platform_compliance_status":"PASS",
        "visual_alignment_findings":[{"segment_id":"N1","alignment_status":"PASS","rationale":"Visual metaphor supports the narration"}],
        "audio_visual_findings":[{"start_seconds":0,"end_seconds":2,"masks_narration":False}],
        "caption_findings":[{"segment_id":"N1","text_match":True,"timing_match":True,"safe_area_pass":True}],
        "technical_export":{
            "expected_aspect_ratio":"9:16","actual_aspect_ratio":"9:16",
            "expected_runtime_seconds":30,"actual_runtime_seconds":30,
            "expected_resolution":"1080x1920","actual_resolution":"1080x1920",
            "expected_fps":30,"actual_fps":30,
        },
    }

def failure_evidence(**overrides):
    diagnostic={
        "affected_capability":"CAP-09",
        "stage":"video_generation",
        "model_or_tool":"Gemini Omni Flash 1.2",
        "tool_version":"1.2",
        "prompt_version":"RS-PWW-001-PROMPT-V1",
        "expected_behavior":"Portrait 9:16 output with one continuous action",
        "observed_behavior":"Generated output is landscape",
        "root_cause_status":"NOT_ESTABLISHED",
        "corrective_action":"Verify actual UI orientation and generation settings",
        "reproduction_steps":["Select portrait orientation","Generate the same prompt","Record actual output dimensions"],
        "evidence_references":["asset:clip-01","prompt:RS-PWW-001-PROMPT-V1"],
        "security_or_rights_risk":False,
        "retest_status":"NOT_RUN",
    }
    diagnostic.update(overrides)
    return {
        "failure_record":{"category":"TOOL","severity":"MEDIUM"},
        "reproduction_or_observation":"Clip output was landscape rather than portrait.",
        "diagnostic_evidence":diagnostic,
    }

class MultiDimensionalQualityTests(unittest.TestCase):
    def test_cap11_accepts_consistent_qc_evidence_for_human_acceptance(self):
        scores={key:95 for key in ("biblical_integrity","script_narration","narrative","visual","audio","technical","rights_provenance","security_compliance","audience_suitability")}
        result=assess_specialist("CAP-11",{"quality_dimensions":scores,"hard_stop_findings":[],"qc_evidence":qc_evidence()})
        self.assertEqual(result["release_recommendation"],"ELIGIBLE_FOR_HUMAN_ACCEPTANCE")

    def test_cap11_blocks_exact_narration_mismatch(self):
        scores={key:100 for key in ("biblical_integrity","script_narration","narrative","visual","audio","technical","rights_provenance","security_compliance","audience_suitability")}
        qc=qc_evidence(); qc["final_transcript_text"]="Look toward the light and pray."
        result=assess_specialist("CAP-11",{"quality_dimensions":scores,"hard_stop_findings":[],"qc_evidence":qc})
        self.assertIn("NARRATION_TEXT_MISMATCH",result["hard_stop_findings"])
        self.assertEqual(result["release_recommendation"],"BLOCKED_BY_HARD_STOP")

    def test_cap11_blocks_audio_masking_and_visual_contradiction(self):
        scores={key:100 for key in ("biblical_integrity","script_narration","narrative","visual","audio","technical","rights_provenance","security_compliance","audience_suitability")}
        qc=qc_evidence()
        qc["audio_visual_findings"][0]["masks_narration"]=True
        qc["visual_alignment_findings"][0]["alignment_status"]="CONTRADICTS"
        result=assess_specialist("CAP-11",{"quality_dimensions":scores,"hard_stop_findings":[],"qc_evidence":qc})
        self.assertTrue(any(x.startswith("AUDIO_MASKS_NARRATION") for x in result["hard_stop_findings"]))
        self.assertTrue(any(x.startswith("VISUAL_ALIGNMENT_CONTRADICTS") for x in result["hard_stop_findings"]))

    def test_cap11_blocks_technical_export_mismatch_and_requires_rights_review(self):
        scores={key:100 for key in ("biblical_integrity","script_narration","narrative","visual","audio","technical","rights_provenance","security_compliance","audience_suitability")}
        qc=qc_evidence()
        qc["technical_export"]["actual_aspect_ratio"]="16:9"
        qc["rights_status"]="REVIEW"
        result=assess_specialist("CAP-11",{"quality_dimensions":scores,"hard_stop_findings":[],"qc_evidence":qc})
        self.assertIn("ASPECT_RATIO_MISMATCH",result["hard_stop_findings"])
        self.assertIn("RIGHTS_STATUS_REVIEW_REQUIRED",result["derived_qc_flags"])

class FailureIntelligenceTests(unittest.TestCase):
    def test_cap14_records_unknown_root_cause_without_claiming_confirmation(self):
        result=assess_specialist("CAP-14",failure_evidence())
        self.assertEqual(result["root_cause_status"],"NOT_ESTABLISHED")
        self.assertFalse(result["automatic_retry_authorised"])
        self.assertEqual(result["retry_policy"],"NO_AUTOMATIC_RETRY_UNTIL_TRIAGED")

    def test_cap14_requires_evidence_for_confirmed_root_cause(self):
        evidence=failure_evidence(root_cause_status="CONFIRMED",root_cause_evidence="")
        result=assess_specialist("CAP-14",evidence)
        self.assertIn("ROOT_CAUSE_CONFIRMATION_UNSUPPORTED",result["diagnostic_flags"])
        self.assertIn("root_cause_evidence",result["missing_diagnostic_fields"])

    def test_cap14_blocks_retry_for_security_or_rights_risk(self):
        result=assess_specialist("CAP-14",failure_evidence(security_or_rights_risk=True))
        self.assertEqual(result["retry_policy"],"BLOCKED_PENDING_SECURITY_OR_RIGHTS_REVIEW")
        self.assertFalse(result["automatic_retry_authorised"])

    def test_cap14_rights_or_security_category_blocks_even_if_risk_flag_is_false(self):
        result=assess_specialist("CAP-14",failure_evidence(security_or_rights_risk=False))
        self.assertEqual(result["retry_policy"],"NO_AUTOMATIC_RETRY_UNTIL_TRIAGED")
        security=failure_evidence(security_or_rights_risk=False)
        security["failure_record"]["category"]="SECURITY"
        confirmed=security["diagnostic_evidence"]
        confirmed["root_cause_status"]="CONFIRMED"
        confirmed["root_cause_evidence"]="verified security incident evidence"
        blocked=assess_specialist("CAP-14",security)
        self.assertEqual(blocked["retry_policy"],"BLOCKED_PENDING_SECURITY_OR_RIGHTS_REVIEW")

    def test_cap14_requires_retest_evidence_for_pass(self):
        result=assess_specialist("CAP-14",failure_evidence(retest_status="PASS",retest_evidence=""))
        self.assertIn("retest_evidence",result["missing_diagnostic_fields"])

if __name__=="__main__":
    unittest.main()
