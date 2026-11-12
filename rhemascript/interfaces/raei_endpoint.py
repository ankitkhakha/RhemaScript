"""Local RAEI service endpoint; intentionally not assigned an IF identifier.

The endpoint validates the shared request envelope, applies disclosure checks,
and dispatches only to the explicitly read-only RAEI adapter. It has no provider
transport, write operation, or generic InterfaceGateway registration.
"""
from __future__ import annotations

import json
from typing import Any

from rhemascript.core.disclosure import DisclosureError, disclose
from raei.interface_adapter import RAEIAdapterError, RAEIReadOnlyAdapter


class RAEIEndpointError(ValueError):
    """Raised when a local RAEI endpoint request is invalid or denied."""


_REQUIRED = {"request_id", "project_id", "operation", "payload", "source_version"}
_OPTIONAL = {"classification"}


class RAEIReadOnlyEndpoint:
    """Strict local request boundary for the RAEI read-only service."""

    def __init__(self, adapter: RAEIReadOnlyAdapter):
        if not isinstance(adapter, RAEIReadOnlyAdapter):
            raise RAEIEndpointError("an explicit RAEIReadOnlyAdapter is required")
        self._adapter = adapter

    def invoke(
        self,
        request: dict[str, Any],
        *,
        recipient_clearance: str = "OPERATIONAL",
        task_need: bool = True,
        approved_scope: bool = True,
    ) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise RAEIEndpointError("request must be an object")
        fields = set(request)
        if not _REQUIRED.issubset(fields) or fields - _REQUIRED - _OPTIONAL:
            raise RAEIEndpointError("request fields do not match the RAEI endpoint contract")
        for field in ("request_id", "project_id", "operation", "source_version"):
            value = request[field]
            if not isinstance(value, str) or not value.strip():
                raise RAEIEndpointError(f"{field} must be a non-empty string")
        if not isinstance(request["payload"], dict):
            raise RAEIEndpointError("payload must be an object")
        try:
            snapshot = json.loads(json.dumps(
                request, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ))
        except (TypeError, ValueError):
            raise RAEIEndpointError("request must contain only finite JSON data") from None
        classification = snapshot.get("classification", "OPERATIONAL")
        if not isinstance(classification, str) or not classification.strip():
            raise RAEIEndpointError("classification must be a non-empty string")
        try:
            disclose(
                item_classification=classification,
                recipient_clearance=recipient_clearance,
                task_need=task_need,
                approved_scope=approved_scope,
            )
        except DisclosureError:
            raise RAEIEndpointError("disclosure denied") from None
        try:
            result = self._adapter.invoke(snapshot["operation"], snapshot["payload"])
        except RAEIAdapterError as exc:
            raise RAEIEndpointError(str(exc)) from None
        return {
            "request_id": snapshot["request_id"],
            "project_id": snapshot["project_id"],
            "source_version": snapshot["source_version"],
            "status": "COMPLETED_READ_ONLY",
            "result": result,
            "provider_call_performed": False,
            "write_performed": False,
        }
