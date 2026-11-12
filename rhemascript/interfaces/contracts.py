"""Provider-neutral request contracts for RhemaScript local interface adapters.

IF-01..IF-18 semantic mappings remain intentionally unresolved. This module
validates only the shared transport envelope; it does not invent interface
business semantics or enable external execution.
"""
from __future__ import annotations

import json
from typing import Any

from rhemascript.registry.system_registry import INTERFACES


class InterfaceContractError(ValueError):
    """Raised when a shared interface request contract is violated."""


REQUIRED_FIELDS = ("request_id", "project_id", "operation", "payload", "source_version")
IDENTIFIER_FIELDS = ("request_id", "project_id", "operation", "source_version")
DANGEROUS_OPERATIONS = frozenset({"GENERATE", "PUBLISH", "SPEND", "EXTERNAL_WRITE"})


def validate_interface_request(interface_id: str, request: dict[str, Any]) -> str:
    """Validate the common envelope and return its canonical SHA-256 fingerprint.

    The fingerprint is deterministic for equivalent JSON objects. It is not a
    durable idempotency guarantee: persistence and cross-process replay control
    remain separate implementation requirements.
    """
    if interface_id not in INTERFACES:
        raise InterfaceContractError(f"unknown interface: {interface_id!r}")
    if not isinstance(request, dict):
        raise InterfaceContractError("request must be an object")

    missing = [field for field in REQUIRED_FIELDS if field not in request]
    if missing:
        raise InterfaceContractError("missing request fields: " + ", ".join(missing))

    for field in IDENTIFIER_FIELDS:
        value = request[field]
        if not isinstance(value, str) or not value.strip():
            raise InterfaceContractError(f"{field} must be a non-empty string")

    if not isinstance(request["payload"], dict):
        raise InterfaceContractError("payload must be an object")

    classification = request.get("classification", "OPERATIONAL")
    if not isinstance(classification, str) or not classification.strip():
        raise InterfaceContractError("classification must be a non-empty string")

    try:
        canonical = json.dumps(
            request, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise InterfaceContractError("request must contain JSON-compatible finite values") from exc

    from hashlib import sha256
    return sha256(canonical.encode("utf-8")).hexdigest()
