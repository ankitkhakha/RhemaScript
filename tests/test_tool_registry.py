import unittest
from datetime import date

from rhemascript.capabilities.tool_registry import (
    CAPABILITY_REGISTRY, REGISTRY_VERSION, assess_tool_preflight,
    find_capability,
)
from rhemascript.capabilities.specialists import assess_specialist

def flow_request(**overrides):
    request = {
        "provider": "google",
        "interface": "flow_web",
        "model": "gemini-omni-flash-1.2",
        "operation": "text_to_video",
        "duration_seconds": 10,
        "aspect_ratio": "9:16",
        "resolution": "720p",
        "plan_tier": "NONE",
        "region_status": "USER_CONFIRMED_AVAILABLE",
        "ui_settings_confirmed": True,
        "selected_model_confirmed": True,
    }
    request.update(overrides)
    return request

def flow_evidence(request=None, checked_at="2026-11-11", source_url="https://support.google.com/flow/answer/16352836"):
    req = request or flow_request()
    return {
        "target_platform": "YouTube Shorts",
        "generation_request": req,
        "verified_tool_evidence": [{
            "provider": req["provider"],
            "interface": req["interface"],
            "model": req["model"],
            "operation": req["operation"],
            "knowledge_state": "VERIFIED_CURRENT",
            "checked_at": checked_at,
            "source_url": source_url,
        }],
    }

class ToolRegistryTests(unittest.TestCase):
    def test_registry_is_versioned_and_has_supported_flow_operations(self):
        self.assertTrue(REGISTRY_VERSION)
        self.assertIsNotNone(find_capability("google", "flow_web", "gemini-omni-flash-1.2", "omni_extend"))
        self.assertGreaterEqual(len(CAPABILITY_REGISTRY), 7)

    def test_current_official_evidence_and_confirmed_portrait_settings_pass(self):
        result = assess_tool_preflight(flow_evidence(), as_of=date(2026, 11, 11))
        self.assertEqual(result["preflight_status"], "COMPATIBLE_FOR_HUMAN_REVIEW")
        self.assertEqual(result["blocking_flags"], [])
        self.assertFalse(result["generation_authorised"])
        self.assertFalse(result["account_or_region_independently_verified"])

    def test_unregistered_or_retired_model_operation_fails_closed(self):
        request = flow_request(model="veo-extend-retired", operation="omni_extend", plan_tier="PRO")
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertIn("UNSUPPORTED_OR_UNREGISTERED_OPERATION", result["blocking_flags"])
        self.assertEqual(result["preflight_status"], "BLOCKED")

    def test_unsupported_duration_fails_closed(self):
        request = flow_request(duration_seconds=12, plan_tier="NONE")
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertIn("DURATION_UNSUPPORTED", result["blocking_flags"])

    def test_unsupported_aspect_ratio_fails_closed(self):
        request = flow_request(aspect_ratio="1:1")
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertIn("ASPECT_RATIO_UNSUPPORTED", result["blocking_flags"])

    def test_missing_portrait_ui_confirmation_fails_closed(self):
        request = flow_request(ui_settings_confirmed=False)
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertIn("UI_SETTINGS_NOT_CONFIRMED", result["blocking_flags"])

    def test_stale_official_evidence_fails_closed(self):
        result = assess_tool_preflight(flow_evidence(checked_at="2026-09-01"), as_of=date(2026, 11, 11))
        self.assertIn("STALE_OR_FUTURE_DATED_EVIDENCE", result["blocking_flags"])
        self.assertIn("NO_MATCHING_CURRENT_OFFICIAL_EVIDENCE", result["blocking_flags"])

    def test_non_official_evidence_fails_closed(self):
        result = assess_tool_preflight(flow_evidence(source_url="https://example.com/google-flow"), as_of=date(2026, 11, 11))
        self.assertIn("NON_OFFICIAL_SOURCE_0", result["blocking_flags"])

    def test_unknown_plan_and_unconfirmed_region_fail_closed(self):
        request = flow_request(plan_tier="UNKNOWN", region_status="UNKNOWN")
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertIn("PLAN_TIER_INELIGIBLE_OR_UNKNOWN", result["blocking_flags"])
        self.assertIn("REGION_AVAILABILITY_NOT_CONFIRMED", result["blocking_flags"])

    def test_flow_extend_requires_selected_source_and_limits_references(self):
        request = flow_request(
            operation="omni_extend",
            plan_tier="PRO",
            source_clip_selected=False,
            image_reference_count=4,
        )
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertIn("EXTEND_SOURCE_CLIP_NOT_SELECTED", result["blocking_flags"])
        self.assertIn("EXTEND_IMAGE_REFERENCE_LIMIT_EXCEEDED", result["blocking_flags"])

    def test_retired_veo_extend_workflow_is_explicitly_blocked(self):
        request = flow_request(model="veo-3.1-quality", operation="veo_extend", plan_tier="PRO")
        request["source_clip_selected"] = True
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertEqual(result["model_lifecycle"]["status"], "RETIRED")
        self.assertIn("MODEL_OR_WORKFLOW_RETIRED", result["blocking_flags"])

    def test_sunset_scheduled_omni_flash_11_is_flagged_before_retirement(self):
        request = flow_request(model="gemini-omni-flash-1.1")
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertEqual(result["model_lifecycle"]["status"], "SUNSET_SCHEDULED")
        self.assertIn("MODEL_RETIREMENT_SCHEDULED", result["blocking_flags"])

    def test_sunset_model_becomes_retired_on_effective_date(self):
        request = flow_request(model="gemini-omni-flash-1.1")
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 12, 5))
        self.assertEqual(result["model_lifecycle"]["status"], "RETIRED")
        self.assertIn("MODEL_OR_WORKFLOW_RETIRED", result["blocking_flags"])

    def test_flow_extend_with_pro_and_selected_source_can_pass(self):
        request = flow_request(
            operation="omni_extend",
            plan_tier="PRO",
            source_clip_selected=True,
            image_reference_count=3,
        )
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertEqual(result["preflight_status"], "COMPATIBLE_FOR_HUMAN_REVIEW")

    def test_plus_plan_allows_documented_15_second_flow_generation(self):
        request = flow_request(duration_seconds=15, plan_tier="PLUS")
        result = assess_tool_preflight(flow_evidence(request), as_of=date(2026, 11, 11))
        self.assertEqual(result["preflight_status"], "COMPATIBLE_FOR_HUMAN_REVIEW")

    def test_cap09_specialist_wraps_preflight_without_authorising_generation(self):
        result = assess_specialist("CAP-09", flow_evidence())
        preflight = result["tool_preflight"]
        self.assertEqual(preflight["preflight_status"], "COMPATIBLE_FOR_HUMAN_REVIEW")
        self.assertFalse(preflight["generation_authorised"])
        self.assertTrue(result["platform_claims_allowed"])

if __name__ == "__main__":
    unittest.main()
