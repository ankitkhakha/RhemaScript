"""Versioned, evidence-backed AI video capability registry.

This registry is a dated reference snapshot, not a live Google API or account probe.
A caller must supply current official-source evidence and confirm the actual UI state.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

REGISTRY_VERSION = "2026-11-11.1"
REGISTRY_VERIFIED_ON = date(2026, 11, 11)
MAX_EVIDENCE_AGE_DAYS = 30

FLOW_MODEL = "gemini-omni-flash-1.2"
GEMINI_APP_MODEL = "gemini-omni-flash-1.2"

FLOW_SOURCE = "https://support.google.com/flow/answer/16352836"
FLOW_EDIT_SOURCE = "https://support.google.com/labs/answer/16935718"
GEMINI_SOURCE = "https://support.google.com/gemini/answer/16126339"

@dataclass(frozen=True)
class OperationCapability:
    provider: str
    interface: str
    model: str
    operation: str
    min_seconds: int
    max_seconds: int
    aspect_ratios: tuple[str, ...]
    resolutions: tuple[str, ...]
    eligible_plans: tuple[str, ...]
    source_urls: tuple[str, ...]
    notes: str = ""

# This deliberately records only operations explicitly documented by Google.
# Unknown features are not inferred from neighbouring models or interfaces.
CAPABILITY_REGISTRY: tuple[OperationCapability, ...] = (
    OperationCapability("google", "flow_web", FLOW_MODEL, "text_to_video", 3, 10,
        ("9:16", "16:9"), ("360p", "720p"), ("NONE", "PLUS", "PRO", "ULTRA"),
        (FLOW_SOURCE,), "3-10s without a Google AI subscription; Plus/Pro/Ultra support up to 15s."),
    OperationCapability("google", "flow_web", FLOW_MODEL, "frames_to_video", 3, 10,
        ("9:16", "16:9"), ("360p", "720p"), ("NONE", "PLUS", "PRO", "ULTRA"),
        (FLOW_SOURCE,), "First-frame and first/last-frame workflows; web interface."),
    OperationCapability("google", "flow_web", FLOW_MODEL, "ingredients_to_video", 3, 10,
        ("9:16", "16:9"), ("360p", "720p"), ("NONE", "PLUS", "PRO", "ULTRA"),
        (FLOW_SOURCE,), "Reference/ingredient-to-video workflow."),
    OperationCapability("google", "flow_web", FLOW_MODEL, "video_to_video_edit", 3, 10,
        ("9:16", "16:9"), ("360p", "720p"), ("NONE", "PLUS", "PRO", "ULTRA"),
        (FLOW_SOURCE, FLOW_EDIT_SOURCE), "Edit a selected video segment; Plus/Pro/Ultra allow up to 15s."),
    OperationCapability("google", "flow_web", FLOW_MODEL, "omni_extend", 3, 10,
        ("9:16", "16:9"), ("360p", "720p"), ("PLUS", "PRO", "ULTRA"),
        (FLOW_SOURCE, FLOW_EDIT_SOURCE), "Requires Plus/Pro/Ultra; select an existing clip; up to three image references."),
    OperationCapability("google", "gemini_app", GEMINI_APP_MODEL, "text_to_video", 3, 10,
        ("9:16", "16:9"), (), ("PLUS", "PRO", "ULTRA"),
        (GEMINI_SOURCE,), "AI plan required; up to 15s for Ultra; text prompts default to landscape."),
    OperationCapability("google", "gemini_app", GEMINI_APP_MODEL, "video_to_video_edit", 3, 10,
        ("9:16", "16:9"), (), ("PLUS", "PRO", "ULTRA"),
        (GEMINI_SOURCE,), "Upload one video; supported edit length up to 10s or 15s for Ultra."),
)

def _normal(value: Any) -> str:
    return value.strip().lower() if isinstance(value, str) else ""

def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None

def _official_google_source(url: Any) -> bool:
    if not isinstance(url, str):
        return False
    return url.startswith("https://support.google.com/") or url.startswith("https://support.google.com/labs/")

def find_capability(provider: str, interface: str, model: str, operation: str) -> OperationCapability | None:
    key = (_normal(provider), _normal(interface), _normal(model), _normal(operation))
    for item in CAPABILITY_REGISTRY:
        if (item.provider, item.interface, item.model, item.operation) == key:
            return item
    return None

def assess_tool_preflight(evidence: dict[str, Any], *, as_of: date | None = None) -> dict[str, Any]:
    """Assess a proposed operation; never authorises generation or inspects a live account."""
    if not isinstance(evidence, dict):
        raise ValueError("CAP-09 evidence must be an object")
    request = evidence.get("generation_request")
    verification = evidence.get("verified_tool_evidence")
    if not isinstance(request, dict):
        raise ValueError("generation_request must be an object")
    if not isinstance(verification, list):
        raise ValueError("verified_tool_evidence must be a list")

    today = as_of or datetime.now(timezone.utc).date()
    required = ("provider", "interface", "model", "operation", "duration_seconds",
                "aspect_ratio", "plan_tier", "region_status", "ui_settings_confirmed",
                "selected_model_confirmed")
    missing = [key for key in required if key not in request or request[key] is None or request[key] == ""]
    flags: list[str] = []
    if missing:
        flags.append("MISSING_REQUEST_FIELDS")

    capability = None
    if not missing:
        capability = find_capability(request["provider"], request["interface"], request["model"], request["operation"])
        if capability is None:
            flags.append("UNSUPPORTED_OR_UNREGISTERED_OPERATION")

    if capability is not None:
        duration = request["duration_seconds"]
        if isinstance(duration, bool) or not isinstance(duration, (int, float)):
            flags.append("INVALID_DURATION")
        elif duration < capability.min_seconds or duration > capability.max_seconds:
            # Ultra duration exceptions are explicit and checked separately below.
            ultra_exception = (
                request["interface"] == "gemini_app" and request["plan_tier"] == "ULTRA"
                and request["operation"] in ("text_to_video", "video_to_video_edit")
                and 10 < duration <= 15
            ) or (
                request["interface"] == "flow_web" and request["plan_tier"] in ("PLUS", "PRO", "ULTRA")
                and request["operation"] in ("text_to_video", "frames_to_video", "ingredients_to_video", "video_to_video_edit")
                and 10 < duration <= 15
            )
            if not ultra_exception:
                flags.append("DURATION_UNSUPPORTED")
        if request["aspect_ratio"] not in capability.aspect_ratios:
            flags.append("ASPECT_RATIO_UNSUPPORTED")
        if capability.resolutions and request.get("resolution") not in capability.resolutions:
            flags.append("RESOLUTION_UNSUPPORTED")
        if request["plan_tier"] not in capability.eligible_plans:
            flags.append("PLAN_TIER_INELIGIBLE_OR_UNKNOWN")
        if request["region_status"] != "USER_CONFIRMED_AVAILABLE":
            flags.append("REGION_AVAILABILITY_NOT_CONFIRMED")
        if request["ui_settings_confirmed"] is not True:
            flags.append("UI_SETTINGS_NOT_CONFIRMED")
        if request["selected_model_confirmed"] is not True:
            flags.append("ACTIVE_MODEL_NOT_CONFIRMED")
        if capability.operation == "omni_extend":
            if request.get("source_clip_selected") is not True:
                flags.append("EXTEND_SOURCE_CLIP_NOT_SELECTED")
            refs = request.get("image_reference_count", 0)
            if isinstance(refs, bool) or not isinstance(refs, int) or not 0 <= refs <= 3:
                flags.append("EXTEND_IMAGE_REFERENCE_LIMIT_EXCEEDED")

    matching_evidence = []
    stale_evidence = []
    for index, item in enumerate(verification):
        if not isinstance(item, dict):
            flags.append(f"INVALID_VERIFICATION_RECORD_{index}")
            continue
        if item.get("knowledge_state") != "VERIFIED_CURRENT":
            continue
        checked = _parse_date(item.get("checked_at"))
        if checked is None or (today - checked).days < 0 or (today - checked).days > MAX_EVIDENCE_AGE_DAYS:
            stale_evidence.append(index)
            continue
        if not _official_google_source(item.get("source_url")):
            flags.append(f"NON_OFFICIAL_SOURCE_{index}")
            continue
        if capability and (
            _normal(item.get("provider")) == capability.provider
            and _normal(item.get("interface")) == capability.interface
            and _normal(item.get("model")) == capability.model
            and _normal(item.get("operation")) == capability.operation
            and item.get("source_url") in capability.source_urls
        ):
            matching_evidence.append(index)

    if stale_evidence:
        flags.append("STALE_OR_FUTURE_DATED_EVIDENCE")
    if not matching_evidence:
        flags.append("NO_MATCHING_CURRENT_OFFICIAL_EVIDENCE")

    # Preserve first occurrence while keeping the result deterministic.
    flags = list(dict.fromkeys(flags))
    ready = not flags
    return {
        "registry_version": REGISTRY_VERSION,
        "registry_verified_on": REGISTRY_VERIFIED_ON.isoformat(),
        "evidence_max_age_days": MAX_EVIDENCE_AGE_DAYS,
        "preflight_status": "COMPATIBLE_FOR_HUMAN_REVIEW" if ready else "BLOCKED",
        "blocking_flags": flags,
        "matched_capability": {
            "provider": capability.provider,
            "interface": capability.interface,
            "model": capability.model,
            "operation": capability.operation,
            "supported_duration_seconds": [capability.min_seconds, capability.max_seconds],
            "supported_aspect_ratios": list(capability.aspect_ratios),
            "supported_resolutions": list(capability.resolutions),
            "eligible_plans": list(capability.eligible_plans),
            "notes": capability.notes,
        } if capability else None,
        "matching_evidence_indexes": matching_evidence,
        "stale_evidence_indexes": stale_evidence,
        "generation_authorised": False,
        "account_or_region_independently_verified": False,
        "assessment_boundary": "registry and supplied evidence assessment only; no live Google connection, account inspection, or generation",
    }
