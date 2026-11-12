"""Fail-closed provider transport boundary for explicitly configured integrations.

No provider is configured by default and network access is disabled by default.
This module deliberately does not infer what IF-01..IF-18 connect to.
"""
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
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
    """Stdlib HTTPS transport. Redirects are rejected, never followed."""
    def send_request(self, url: str, method: str, headers: dict[str, str],
                     body: bytes | None, timeout: float) -> tuple[int, bytes, dict[str, str]]:
        req = Request(url, data=body, headers=headers, method=method)
        try:
            opener = build_opener(_NoRedirect())
            with opener.open(req, timeout=timeout) as response:
                return response.status, response.read(8_000_001), dict(getattr(response, "headers", {}).items())
        except HTTPError as exc:
            return exc.code, exc.read(8_000_001), dict(exc.headers.items())
        except URLError as exc:
            raise ExternalIntegrationError("provider transport failed") from None

    def send(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        status, raw, _ = self.send_request(url, "POST", headers, body, timeout)
        return status, raw


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
        self._inflight: dict[str, dict[str, Any]] = {}

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
        if not isinstance(path, str) or not path:
            raise ExternalIntegrationError("operation is not mapped by provider contract")
        relative = urlparse(path)
        decoded_path = unquote(path)
        if (relative.scheme or relative.netloc or relative.query or relative.fragment
                or path.startswith("/") or "\\" in path
                or any(part in {".", ".."} for part in decoded_path.split("/"))
                or any(ord(char) < 32 for char in path)):
            raise ExternalIntegrationError("operation path is not a safe relative provider path")

        if self.audit_sink is None:
            raise ExternalIntegrationError("auditable integration requires an audit sink")
        # This legacy entry point always transmits POST. Require write
        # authority before cache access as well as before provider transport.
        try:
            authorise_action("EXTERNAL_WRITE", authority or {})
        except AuthorityError as exc:
            raise ExternalIntegrationError(
                "generic POST invocation lacks explicit authority: external-write authority is required"
            ) from exc

        parsed = urlparse(binding.endpoint)
        url = binding.endpoint.rstrip("/") + "/" + path
        if urlparse(url).hostname != parsed.hostname:
            raise ExternalIntegrationError("operation mapping changed provider host")
        if urlparse(url).hostname != parsed.hostname:
            raise ExternalIntegrationError("operation mapping changed provider host")
        canonical = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        key = sha256((interface_id + ":" + canonical).encode()).hexdigest()
        # Claim the key before transport. Duplicates wait for this request's
        # terminal result instead of racing into a second provider POST.
        with self._lock:
            cached = self._responses.get(key)
            if cached is not None:
                return json.loads(json.dumps(cached))
            flight = self._inflight.get(key)
            owner = flight is None
            if owner:
                flight = {"event": threading.Event(), "result": None, "error": None}
                self._inflight[key] = flight
        if not owner:
            flight["event"].wait()
            if flight["result"] is not None:
                return json.loads(json.dumps(flight["result"]))
            error = flight["error"]
            if isinstance(error, ExternalIntegrationError):
                raise ExternalIntegrationError(str(error)) from None
            raise ExternalIntegrationError("concurrent duplicate provider invocation failed") from None

        event = {"interface_id": interface_id, "provider": binding.provider_name,
                 "request_id": request["request_id"], "operation": operation,
                 "idempotency_key": key, "phase": "REQUESTED"}
        try:
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
            with self._lock:
                self._responses[key] = result
                flight["result"] = result
            return json.loads(json.dumps(result))
        except Exception as exc:
            flight["error"] = (exc if isinstance(exc, ExternalIntegrationError)
                               else ExternalIntegrationError("provider invocation failed"))
            try:
                event.update({"phase": "FAILED", "error_type": type(exc).__name__})
                self.audit_sink(dict(event))
            except Exception:
                pass
            if isinstance(exc, ExternalIntegrationError):
                raise
            raise ExternalIntegrationError("provider invocation failed") from exc
        finally:
            with self._lock:
                self._inflight.pop(key, None)
                flight["event"].set()

    def request(self, interface_id: str, operation: str, url: str, *,
                method: str, headers: dict[str, str] | None = None,
                body: bytes | None = None, request_id: str,
                project_id: str, source_version: str,
                recipient_clearance: str = "OPERATIONAL",
                task_need: bool = True, approved_scope: bool = True,
                authority: dict[str, bool] | None = None,
                max_response_bytes: int = 8_000_000) -> tuple[int, bytes, dict[str, str]]:
        """Audited method-aware provider request for OAuth and resumable protocols."""
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
        if self.audit_sink is None:
            raise ExternalIntegrationError("auditable integration requires an audit sink")
        if not all(isinstance(x, str) and x.strip() for x in (operation, request_id, project_id, source_version)):
            raise ExternalIntegrationError("request identity fields must be non-empty strings")
        spec = binding.operations.get(operation.upper())
        if not isinstance(spec, dict):
            raise ExternalIntegrationError("operation has no method-aware provider contract")
        expected_method = spec.get("method")
        hosts = spec.get("hosts")
        path_prefix = spec.get("path_prefix")
        if method.upper() != expected_method or not isinstance(hosts, (tuple, list)) or not hosts:
            raise ExternalIntegrationError("HTTP method is not permitted by provider contract")
        if not isinstance(path_prefix, str) or not path_prefix.startswith("/") or ".." in path_prefix.split("/"):
            raise ExternalIntegrationError("provider path contract is invalid")
        parsed = urlparse(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.port not in (None, 443) or parsed.fragment
                or parsed.hostname.lower() not in {h.lower() for h in hosts}
                or not (parsed.path == path_prefix or parsed.path.startswith(path_prefix.rstrip("/") + "/"))):
            raise ExternalIntegrationError("request URL is outside the provider operation allowlist")
        if not isinstance(body, (bytes, type(None))) or not 0 < max_response_bytes <= 8_000_000:
            raise ExternalIntegrationError("request body or response limit is invalid")
        try:
            disclose(item_classification="OPERATIONAL", recipient_clearance=recipient_clearance,
                     task_need=task_need, approved_scope=approved_scope)
        except DisclosureError:
            raise ExternalIntegrationError("disclosure denied") from None
        authority_operation = "PUBLISH" if operation.upper() in {
            "UPLOAD_SESSION", "UPLOAD_CHUNK", "THUMBNAIL_WRITE"
        } else operation.upper()
        if authority_operation in self.CONSEQUENT_OPERATIONS or authority_operation == "PUBLISH":
            try:
                authorise_action(authority_operation, authority or {})
            except AuthorityError:
                raise ExternalIntegrationError("consequential operation lacks explicit authority") from None

        fingerprint = sha256(
            interface_id.encode() + b":" + operation.upper().encode() + b":" +
            method.upper().encode() + b":" + parsed.hostname.encode() + b":" +
            parsed.path.encode() + b":" + sha256(body or b"").digest()
        ).hexdigest()
        event = {"interface_id": interface_id, "provider": binding.provider_name,
                 "request_id": request_id, "project_id": project_id,
                 "operation": operation.upper(), "method": method.upper(),
                 "host": parsed.hostname, "request_fingerprint": fingerprint,
                 "request_bytes": len(body or b""), "phase": "REQUESTED"}
        self.audit_sink(dict(event))
        write_attempted = method.upper() not in {"GET", "HEAD", "OPTIONS"}
        transport_started = False
        response_received = False
        try:
            secret_headers = self.credential_resolver(binding.provider_name)
            if not isinstance(secret_headers, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in secret_headers.items()
            ):
                raise ExternalIntegrationError("credential resolver returned invalid headers")
            request_headers = dict(headers or {})
            if any(not isinstance(k, str) or not isinstance(v, str) for k, v in request_headers.items()):
                raise ExternalIntegrationError("request headers are invalid")
            request_headers.update(secret_headers)
            sender = getattr(self.transport, "send_request", None)
            if sender is None:
                raise ExternalIntegrationError("transport does not support method-aware requests")
            transport_started = True
            status, raw, response_headers = sender(
                url, method.upper(), request_headers, body, binding.timeout_seconds
            )
            response_received = True
            if not isinstance(status, int) or not isinstance(raw, bytes) or not isinstance(response_headers, dict):
                raise ExternalIntegrationError("provider transport returned an invalid response contract")
            if len(raw) > max_response_bytes:
                raise ExternalIntegrationError("provider response exceeds size limit")
            event.update({"phase": "COMPLETED", "http_status": status,
                          "response_bytes": len(raw)})
            try:
                self.audit_sink(dict(event))
            except Exception:
                if write_attempted:
                    event["phase"] = "INDETERMINATE"
                    event["error_type"] = "CompletionAuditFailure"
                    try:
                        self.audit_sink(dict(event))
                    except Exception:
                        pass
                    raise ExternalIntegrationError(
                        "provider write outcome is indeterminate: response received but completion audit failed; do not retry automatically"
                    ) from None
                raise
            return status, raw, response_headers
        except Exception as exc:
            if write_attempted and transport_started and (not response_received or
                    isinstance(exc, ExternalIntegrationError) and "completion audit failed" in str(exc)):
                event.update({"phase": "INDETERMINATE", "error_type": type(exc).__name__})
                try:
                    self.audit_sink(dict(event))
                except Exception:
                    pass
                raise ExternalIntegrationError(
                    "provider write outcome is indeterminate; do not retry automatically until provider state is reconciled"
                ) from None
            event.update({"phase": "FAILED", "error_type": type(exc).__name__})
            self.audit_sink(dict(event))
            if isinstance(exc, ExternalIntegrationError):
                raise
            raise ExternalIntegrationError("provider request failed") from None
