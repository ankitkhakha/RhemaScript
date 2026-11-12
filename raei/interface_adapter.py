"""Read-only RAEI service boundary for future interface adapters.

This module deliberately does not register an IF identifier, dispatch gateway
requests, write learning records, or grant production/publishing authority.
"""
from __future__ import annotations

from typing import Any

from raei.integrity import IntegrityError, validate_project_chain
from raei.project_record import compare_project_records
from raei.store import EvidenceStore, StoreError


class RAEIAdapterError(ValueError):
    """Raised when a read-only RAEI service request is invalid."""


class RAEIReadOnlyAdapter:
    """Explicit read-only facade over project validation and learning evidence."""

    def __init__(self, evidence_store: EvidenceStore):
        if not isinstance(evidence_store, EvidenceStore):
            raise RAEIAdapterError("an explicitly configured EvidenceStore is required")
        self._evidence_store = evidence_store

    @staticmethod
    def validate_project_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(snapshot, dict):
            raise RAEIAdapterError("project snapshot must be an object")
        try:
            result = validate_project_chain(snapshot)
        except IntegrityError as exc:
            raise RAEIAdapterError("project snapshot validation failed") from exc
        return {
            **result,
            "generation_authority": "not_granted_by_adapter",
            "publishing_authority": "not_granted_by_adapter",
        }

    @staticmethod
    def compare_project_snapshots(
        before: dict[str, Any], after: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            result = compare_project_records(before, after)
        except IntegrityError as exc:
            raise RAEIAdapterError("project snapshot comparison failed") from exc
        return {
            **result,
            "generation_authority": "not_granted_by_adapter",
            "publishing_authority": "not_granted_by_adapter",
        }

    def read_learning_unit(self, unit_id: str) -> dict[str, Any]:
        if not isinstance(unit_id, str) or not unit_id.strip():
            raise RAEIAdapterError("unit_id must be a non-empty string")
        try:
            unit = self._evidence_store.get_unit(unit_id)
        except StoreError as exc:
            raise RAEIAdapterError("learning unit could not be read") from exc
        # Return a detached JSON-shaped value; callers cannot mutate store state.
        return {
            "unit": unit,
            "operation": "read_learning_unit",
            "write_performed": False,
            "generation_authority": "not_granted_by_adapter",
            "publishing_authority": "not_granted_by_adapter",
        }

    def invoke(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Dispatch only the three explicitly approved read-only service operations.

        This is a local service boundary, not an IF-01..IF-18 registration.
        """
        if not isinstance(operation, str) or not operation.strip():
            raise RAEIAdapterError("operation must be a non-empty string")
        if not isinstance(payload, dict):
            raise RAEIAdapterError("operation payload must be an object")
        if operation == "VALIDATE_PROJECT_SNAPSHOT":
            if set(payload) != {"snapshot"}:
                raise RAEIAdapterError("validation payload must contain only snapshot")
            result = self.validate_project_snapshot(payload["snapshot"])
        elif operation == "COMPARE_PROJECT_SNAPSHOTS":
            if set(payload) != {"before", "after"}:
                raise RAEIAdapterError("comparison payload must contain before and after")
            result = self.compare_project_snapshots(payload["before"], payload["after"])
        elif operation == "READ_LEARNING_UNIT":
            if set(payload) != {"unit_id"}:
                raise RAEIAdapterError("learning read payload must contain only unit_id")
            result = self.read_learning_unit(payload["unit_id"])
        else:
            raise RAEIAdapterError("operation is not registered on the read-only RAEI adapter")
        return {
            "status": "COMPLETED_READ_ONLY",
            "operation": operation,
            "result": result,
            "write_performed": False,
            "generation_authority": "not_granted_by_adapter",
            "publishing_authority": "not_granted_by_adapter",
        }
