"""Evidence-based readiness assessment; never represents independent certification."""
from dataclasses import dataclass
from typing import Any

REQUIRED_DOMAINS = (
    "provider_contracts", "identity_and_secrets", "network_and_data_controls",
    "idempotency_and_recovery", "audit_and_monitoring", "security_testing",
    "production_e2e", "independent_review",
)

@dataclass(frozen=True)
class AssuranceResult:
    status: str
    passed_domains: tuple[str, ...]
    missing_domains: tuple[str, ...]
    independence_verified: bool


def assess_production_readiness(evidence: dict[str, Any]) -> AssuranceResult:
    if not isinstance(evidence, dict):
        raise ValueError("assurance evidence must be an object")
    passed = []
    missing = []
    for domain in REQUIRED_DOMAINS:
        item = evidence.get(domain)
        if not isinstance(item, dict) or item.get("status") != "VERIFIED" or not item.get("evidence_ref"):
            missing.append(domain)
        else:
            passed.append(domain)
    review = evidence.get("independent_review", {})
    independent = (isinstance(review, dict)
                   and review.get("status") == "VERIFIED"
                   and bool(review.get("evidence_ref"))
                   and bool(review.get("reviewer_id"))
                   and review.get("reviewer_id") != evidence.get("implementation_owner_id"))
    if not independent and "independent_review" not in missing:
        missing.append("independent_review")
        passed.remove("independent_review")
    status = "PRODUCTION_READY_FOR_RELEASE_REVIEW" if not missing else "NOT_PRODUCTION_READY"
    return AssuranceResult(status, tuple(passed), tuple(missing), independent)
