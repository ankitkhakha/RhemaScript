"""18 registered runtime interface adapters. No external network calls or writes occur."""
from dataclasses import dataclass
import json
from typing import Any

from rhemascript.registry.system_registry import INTERFACES
from rhemascript.core.disclosure import disclose, DisclosureError
from rhemascript.core.authority import authorise_action, AuthorityError
from rhemascript.interfaces.contracts import (
    DANGEROUS_OPERATIONS, InterfaceContractError, validate_interface_request,
)


class InterfaceError(ValueError):
    pass


@dataclass(frozen=True)
class InterfaceResponse:
    interface_id: str
    status: str
    request_id: str
    payload: dict[str, Any]
    idempotency_key: str


class InterfaceGateway:
    def __init__(self):
        self.adapters = {iid: self._handle for iid in INTERFACES}
        # Process-local replay cache only. This is not durable/cross-process
        # idempotency and must not be represented as such in readiness claims.
        self._seen: dict[str, InterfaceResponse] = {}

    def invoke(
        self,
        interface_id: str,
        request: dict[str, Any],
        *,
        recipient_clearance: str = "OPERATIONAL",
        task_need: bool = True,
        approved_scope: bool = True,
        authority: dict[str, bool] | None = None,
    ) -> InterfaceResponse:
        if interface_id not in self.adapters:
            raise InterfaceError("unknown interface")
        try:
            key = validate_interface_request(interface_id, request)
        except InterfaceContractError as exc:
            raise InterfaceError(str(exc)) from exc

        classification = request.get("classification", "OPERATIONAL")
        try:
            disclose(
                item_classification=classification,
                recipient_clearance=recipient_clearance,
                task_need=task_need,
                approved_scope=approved_scope,
            )
        except DisclosureError as exc:
            raise InterfaceError(str(exc)) from exc

        # Canonicalise before the consequential-action check so casing or
        # surrounding whitespace cannot bypass the existing authority guard.
        operation = request["operation"].strip().upper()
        if operation in DANGEROUS_OPERATIONS:
            try:
                authorise_action(operation, authority or {})
            except AuthorityError as exc:
                raise InterfaceError(str(exc)) from exc

        # Snapshot validated JSON input so later caller mutation cannot alter a
        # cached response or change what the gateway accepted.
        snapshot = json.loads(json.dumps(
            request, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ))
        if key in self._seen:
            return self._copy_response(self._seen[key])
        result = self._handle(interface_id, snapshot, key)
        self._seen[key] = self._copy_response(result)
        return self._copy_response(result)

    @staticmethod
    def _copy_response(response: InterfaceResponse) -> InterfaceResponse:
        return InterfaceResponse(
            response.interface_id,
            response.status,
            response.request_id,
            json.loads(json.dumps(response.payload, sort_keys=True, ensure_ascii=False)),
            response.idempotency_key,
        )

    @staticmethod
    def _handle(interface_id, request, key):
        return InterfaceResponse(
            interface_id,
            "ACCEPTED_FOR_LOCAL_PROCESSING",
            request["request_id"],
            {
                "project_id": request["project_id"],
                "operation": request["operation"],
                "source_version": request["source_version"],
                "payload": request["payload"],
            },
            key,
        )
