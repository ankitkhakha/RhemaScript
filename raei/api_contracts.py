"""Small deny-by-default authorization and request-validation practical.

This is a deterministic policy exercise, not a production identity provider.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class RequestError(ValueError):
    pass


class AuthorizationError(PermissionError):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class Rule:
    role: str
    action: str
    resource: str


class Policy:
    def __init__(self, rules: tuple[Rule, ...] = ()):
        self._rules = frozenset(rules)

    def permits(self, principal: Principal | None, action: str, resource: str) -> bool:
        if principal is None or not principal.authenticated:
            return False
        if not principal.subject.strip():
            return False
        return any(
            Rule(role, action, resource) in self._rules
            for role in principal.roles
        )

    def require(self, principal: Principal | None, action: str, resource: str) -> None:
        if not self.permits(principal, action, resource):
            raise AuthorizationError("access denied")


def validate_unit_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RequestError("request body must be an object")
    allowed = {"unit_id", "title", "prerequisites"}
    unknown = set(payload) - allowed
    if unknown:
        raise RequestError(f"unknown fields: {', '.join(sorted(unknown))}")
    unit_id = payload.get("unit_id")
    title = payload.get("title")
    prerequisites = payload.get("prerequisites", [])
    if not isinstance(unit_id, str) or not re.fullmatch(r"[A-Z][A-Z0-9_-]{1,63}", unit_id):
        raise RequestError("unit_id must match the documented identifier format")
    if not isinstance(title, str) or not title.strip() or len(title) > 160:
        raise RequestError("title must contain 1 to 160 characters")
    if not isinstance(prerequisites, list) or len(prerequisites) > 32:
        raise RequestError("prerequisites must be a list of at most 32 identifiers")
    if any(not isinstance(item, str) or not re.fullmatch(r"[A-Z][A-Z0-9_-]{1,63}", item)
           for item in prerequisites):
        raise RequestError("each prerequisite must be a valid unit identifier")
    if len(prerequisites) != len(set(prerequisites)):
        raise RequestError("prerequisites must not contain duplicates")
    if unit_id in prerequisites:
        raise RequestError("a unit cannot depend on itself")
    return {"unit_id": unit_id, "title": title.strip(), "prerequisites": prerequisites.copy()}


def validate_assessment_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RequestError("request body must be an object")
    allowed = {"score", "evidence_ref", "evidence_status", "expected_version"}
    unknown = set(payload) - allowed
    if unknown:
        raise RequestError(f"unknown fields: {', '.join(sorted(unknown))}")
    score = payload.get("score")
    version = payload.get("expected_version")
    evidence_ref = payload.get("evidence_ref")
    evidence_status = payload.get("evidence_status")
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 4:
        raise RequestError("score must be an integer from 0 to 4")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RequestError("expected_version must be a positive integer")
    if evidence_status not in {"verified", "reported_unverified", "planned"}:
        raise RequestError("invalid evidence_status")
    if evidence_ref is not None and (not isinstance(evidence_ref, str) or len(evidence_ref) > 512):
        raise RequestError("evidence_ref must be a string of at most 512 characters")
    if evidence_status == "verified" and (not isinstance(evidence_ref, str) or not evidence_ref.strip()):
        raise RequestError("verified evidence requires a non-empty reference")
    return {"score": score, "evidence_ref": evidence_ref,
            "evidence_status": evidence_status, "expected_version": version}
