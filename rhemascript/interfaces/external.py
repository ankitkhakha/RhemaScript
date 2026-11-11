"""Fail-closed provider transport boundary for explicitly configured integrations.

No provider is configured by default and network access is disabled by default.
This module deliberately does not infer what IF-01..IF-18 connect to.
"""
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
import json
import threading


class ExternalIntegrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderBinding:
    interface_id: str
    provider_name: str
    endpoint: str
    allowed_hosts: tuple[str, ...]
    operations: dict[str, str]
    timeout_seconds: float = 10.0
    idempotency_header: str = "Idempotency-Key"

    def validate(self) -> None:
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ExternalIntegrationError("provider endpoint must use HTTPS")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ExternalIntegrationError("endpoint must not contain credentials, query, or fragment")
        if parsed.hostname.lower() not in {h.lower() for h in self.allowed_hosts}:
            raise ExternalIntegrationError("provider host is not explicitly allowlisted")
        if not self.interface_id or not self.provider_name or not self.operations:
            raise ExternalIntegrationError("provider binding is incomplete")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 60:
            raise ExternalIntegrationError("timeout must be between 0 and 60 seconds")


class Transport(Protocol):
    def send(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]: ...


class _NoRedirect(HTTPRedirectHandler):
    """Reject redirects so provider credentials never follow an untrusted hop."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    """Small stdlib HTTPS transport. Redirects are rejected, never followed."""
    def send(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        req = Request(url, data=body, headers=headers, method="POST")
        try:
            opener = build_opener(_NoRedirect())
            with opener.open(req, timeout=timeout) as response:
                return response.status, response.read(2_000_001)
        except HTTPError as exc:
            return exc.code, exc.read(2_000_001)
        except URLError as exc:
            raise ExternalIntegrationError("provider transport failed") from exc


class ExternalIntegrationGateway:
    """Explicitly enabled, allowlisted provider gateway with auditable boundaries."""
    CONSEQUENT_OPERATIONS = {"GENERATE", "PUBLISH", "SPEND", "EXTERNAL_WRITE"}

    def __init__(self, bindings: tuple[ProviderBinding, ...] = (), *,
                 transport: Transport | None = None,
                 credential_resolver: Callable[[str], dict[str, str]] | None = None,
                 audit_sink: Callable[[dict[str, Any]], None] | None = None,
                 enabled: bool = False):
        self.bindings = {}
        for binding in bindings:
            binding.validate()
            if binding.interface_id in self.bindings:
                raise ExternalIntegrationError("duplicate interface provider binding")
            self.bindings[binding.interface_id] = binding
        self.transport = transport or UrllibTransport()
        self.credential_resolver = credential_resolver or (lambda _provider: {})
        self.audit_sink = audit_sink
        self.enabled = enabled
        self._lock = threading.Lock()
        self._responses = {}

    def invoke(self, interface_id: str, request: dict[str, Any], *,
               recipient_clearance: str = "OPERATIONAL", task_need: bool = True,
               approved_scope: bool = True, authority: dict[str, bool] | None = None) -> dict[str, Any]:
        from rhemascript.core.authority import authorise_action, AuthorityError
        from rhemascript.core.disclosure import disclose, DisclosureError
        from rhemascript.registry.system_registry import INTERFACES

        if interface_id not in INTERFACES:
            raise ExternalIntegrationError("unknown interface")
        if not self.enabled:
            raise ExternalIntegrationError("external integration is disabled")
        binding = self.bindings.get(interface_id)
        if binding is None:
            raise ExternalIntegrationError("no provider contract configured for interface")
        if not isinstance(request, dict):
            raise ExternalIntegrationError("request must be an object")
        required = ("request_id", "project_id", "operation", "payload", "source_version")
        if any(k not in request for k in required):
            raise ExternalIntegrationError("request is missing required contract fields")
        if any(not isinstance(request[k], str) or not request[k].strip()
               for k in ("request_id", "project_id", "operation", "source_version")):
            raise ExternalIntegrationError("request identity fields must be non-empty strings")
        if not isinstance(request["payload"], dict):
            raise ExternalIntegrationError("payload must be an object")
        try:
            disclose(item_classification=request.get("classification", "OPERATIONAL"),
                     recipient_clearance=recipient_clearance, task_need=task_need,
                     approved_scope=approved_scope)
        except DisclosureError as exc:
            raise ExternalIntegrationError("disclosure denied") from exc

        operation = request["operation"].upper()
        path = binding.operations.get(operation)
        if not path or path.startswith("//") or "://" in path:
            raise ExternalIntegrationError("operation is not mapped by provider contract")
        if operation in self.CONSEQUENT_OPERATIONS:
            try:
                authorise_action(operation, authority or {})
            except AuthorityError as exc:
                raise ExternalIntegrationError("consequential operation lacks explicit authority") from exc

        parsed = urlparse(binding.endpoint)
        url = binding.endpoint.rstrip("/") + "/" + path.lstrip("/")
        if urlparse(url).hostname != parsed.hostname:
            raise ExternalIntegrationError("operation mapping changed provider host")
        canonical = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        key = sha256((interface_id + ":" + canonical).encode()).hexdigest()
        with self._lock:
            if key in self._responses:
                return self._responses[key]

        if self.audit_sink is None:
            raise ExternalIntegrationError("auditable integration requires an audit sink")
        event = {"interface_id": interface_id, "provider": binding.provider_name,
                 "request_id": request["request_id"], "operation": operation,
                 "idempotency_key": key, "phase": "REQUESTED"}
        self.audit_sink(dict(event))
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   binding.idempotency_header: key}
        secret_headers = self.credential_resolver(binding.provider_name)
        if not isinstance(secret_headers, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                                       for k, v in secret_headers.items()):
            raise ExternalIntegrationError("credential resolver returned invalid headers")
        headers.update(secret_headers)
        body = json.dumps({"project_id": request["project_id"], "request_id": request["request_id"],
                           "operation": operation, "source_version": request["source_version"],
                           "payload": request["payload"]}, separators=(",", ":")).encode()
        try:
            status, raw = self.transport.send(url, headers, body, binding.timeout_seconds)
            if len(raw) > 2_000_000:
                raise ExternalIntegrationError("provider response exceeds size limit")
            if status < 200 or status >= 300:
                raise ExternalIntegrationError(f"provider returned HTTP {status}")
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ExternalIntegrationError("provider returned invalid JSON") from exc
            if not isinstance(payload, dict):
                raise ExternalIntegrationError("provider response must be a JSON object")
            result = {"status": "PROVIDER_CONFIRMED", "provider": binding.provider_name,
                      "interface_id": interface_id, "request_id": request["request_id"],
                      "idempotency_key": key, "http_status": status, "payload": payload}
            event.update({"phase": "COMPLETED", "http_status": status})
            self.audit_sink(dict(event))
        except Exception as exc:
            event.update({"phase": "FAILED", "error_type": type(exc).__name__})
            self.audit_sink(dict(event))
            if isinstance(exc, ExternalIntegrationError):
                raise
            raise ExternalIntegrationError("provider invocation failed") from exc
        with self._lock:
            self._responses[key] = result
        return result
