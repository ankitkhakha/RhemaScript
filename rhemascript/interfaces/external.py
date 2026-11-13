"""Fail-closed provider transport boundary for explicitly configured integrations.

No provider is configured by default and network access is disabled by default.
This module deliberately does not infer what IF-01..IF-18 connect to.
"""
from dataclasses import dataclass
from collections.abc import Mapping
from hashlib import sha256
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
import json
import math
import threading
from types import MappingProxyType


class ExternalIntegrationError(RuntimeError):
    pass


def _safe_decoded_path(path: str) -> str:
    """Decode path escapes repeatedly and reject traversal or separator tricks."""
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ExternalIntegrationError("provider path must be an absolute single-root path")
    decoded = path
    for _ in range(8):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    else:
        raise ExternalIntegrationError("provider path has excessive nested encoding")
    if unquote(decoded) != decoded:
        raise ExternalIntegrationError("provider path has excessive nested encoding")
    if "\\" in decoded or "\x00" in decoded:
        raise ExternalIntegrationError("provider path contains an unsafe separator or null byte")
    if any(part in {".", ".."} for part in decoded.split("/")):
        raise ExternalIntegrationError("provider path contains traversal segments")
    return decoded


@dataclass(frozen=True)
class ProviderBinding:
    interface_id: str
    provider_name: str
    endpoint: str
    allowed_hosts: tuple[str, ...]
    operations: Mapping[str, Any]
    timeout_seconds: float = 10.0
    idempotency_header: str = "Idempotency-Key"

    def validate(self) -> None:
        if (not isinstance(self.interface_id, str) or not self.interface_id.strip()
                or not isinstance(self.provider_name, str) or not self.provider_name.strip()):
            raise ExternalIntegrationError("provider binding identity is incomplete")
        if not isinstance(self.endpoint, str) or not self.endpoint.strip():
            raise ExternalIntegrationError("provider endpoint must be a non-empty URL")
        parsed = urlparse(self.endpoint)
        if (parsed.scheme.lower() != "https" or not parsed.hostname
                or parsed.port not in (None, 443)):
            raise ExternalIntegrationError("provider endpoint must use HTTPS on port 443")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ExternalIntegrationError("endpoint must not contain credentials, query, or fragment")
        if (not isinstance(self.allowed_hosts, (tuple, list)) or not self.allowed_hosts
                or any(not isinstance(host, str) or not host.strip()
                       or host != host.strip() or any(char.isspace() for char in host)
                       or any(char in host for char in "/@?#")
                       or any(ord(char) == 92 for char in host)
                       for host in self.allowed_hosts)):
            raise ExternalIntegrationError("provider host allowlist is invalid")
        allowed = {host.rstrip(".").lower() for host in self.allowed_hosts}
        if parsed.hostname.rstrip(".").lower() not in allowed:
            raise ExternalIntegrationError("provider host is not explicitly allowlisted")
        if not isinstance(self.operations, Mapping) or not self.operations:
            raise ExternalIntegrationError("provider binding requires operation contracts")
        if (not isinstance(self.timeout_seconds, (int, float))
                or isinstance(self.timeout_seconds, bool)
                or not math.isfinite(self.timeout_seconds)
                or self.timeout_seconds <= 0 or self.timeout_seconds > 60):
            raise ExternalIntegrationError("timeout must be finite and between 0 and 60 seconds")

        for operation, spec in self.operations.items():
            if not isinstance(operation, str) or not operation.strip():
                raise ExternalIntegrationError("provider operation names must be non-empty strings")
            if isinstance(spec, str):
                if not spec.strip():
                    raise ExternalIntegrationError("provider operation path must be non-empty")
                continue
            if not isinstance(spec, Mapping):
                raise ExternalIntegrationError("provider operation contract must be a path or object")
            method = spec.get("method")
            hosts = spec.get("hosts")
            path_prefix = spec.get("path_prefix")
            if not isinstance(method, str) or method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                raise ExternalIntegrationError("method-aware provider contract has an invalid HTTP method")
            if (not isinstance(hosts, (tuple, list)) or not hosts
                    or any(not isinstance(host, str) or not host.strip() for host in hosts)):
                raise ExternalIntegrationError("method-aware provider contract has invalid hosts")
            if any(host.rstrip(".").lower() not in allowed for host in hosts):
                raise ExternalIntegrationError("method-aware provider contract host exceeds binding allowlist")
            try:
                _safe_decoded_path(path_prefix)
            except ExternalIntegrationError as exc:
                raise ExternalIntegrationError("method-aware provider contract has an invalid path prefix") from exc
            if "?" in path_prefix or "#" in path_prefix:
                raise ExternalIntegrationError("method-aware provider contract has an invalid path prefix")


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
        configured_bindings = {}
        for binding in bindings:
            binding.validate()
            if binding.interface_id in configured_bindings:
                raise ExternalIntegrationError("duplicate interface provider binding")
            # Snapshot and freeze caller-owned configuration. A frozen dataclass
            # alone does not freeze nested dictionaries or lists.
            frozen_operations = {}
            for operation, spec in binding.operations.items():
                if isinstance(spec, Mapping):
                    spec_copy = dict(spec)
                    if isinstance(spec_copy.get("hosts"), (tuple, list)):
                        spec_copy["hosts"] = tuple(spec_copy["hosts"])
                    frozen_operations[operation] = MappingProxyType(spec_copy)
                else:
                    frozen_operations[operation] = spec
            frozen_binding = ProviderBinding(
                interface_id=binding.interface_id,
                provider_name=binding.provider_name,
                endpoint=binding.endpoint,
                allowed_hosts=tuple(binding.allowed_hosts),
                operations=MappingProxyType(frozen_operations),
                timeout_seconds=binding.timeout_seconds,
                idempotency_header=binding.idempotency_header,
            )
            frozen_binding.validate()
            configured_bindings[frozen_binding.interface_id] = frozen_binding
        self.bindings = MappingProxyType(configured_bindings)
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
                authority: dict[str, Any] | None = None,
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
        if not isinstance(spec, Mapping):
            raise ExternalIntegrationError("operation has no method-aware provider contract")
        expected_method = spec.get("method")
        hosts = spec.get("hosts")
        path_prefix = spec.get("path_prefix")
        if (not isinstance(method, str) or method.upper() != expected_method.upper()
                or not isinstance(hosts, (tuple, list)) or not hosts):
            raise ExternalIntegrationError("HTTP method is not permitted by provider contract")
        if not isinstance(url, str) or not url:
            raise ExternalIntegrationError("request URL must be a non-empty string")
        try:
            parsed = urlparse(url)
            decoded_path = _safe_decoded_path(parsed.path)
            decoded_prefix = _safe_decoded_path(path_prefix)
        except (ValueError, ExternalIntegrationError) as exc:
            raise ExternalIntegrationError("request URL is outside the provider operation allowlist") from exc
        allowed_hosts = {host.rstrip(".").lower() for host in hosts}
        prefix = decoded_prefix.rstrip("/") or "/"
        if (parsed.scheme.lower() != "https" or not parsed.hostname
                or parsed.username or parsed.password or parsed.port not in (None, 443)
                or parsed.fragment or parsed.hostname.rstrip(".").lower() not in allowed_hosts
                or not (decoded_path == prefix or decoded_path.startswith(prefix.rstrip("/") + "/"))):
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
        if authority_operation == "PUBLISH":
            from datetime import datetime, timezone
            from rhemascript.core.approvals import is_verified_approval
            approvals = (authority or {}).get("verified_approvals")
            now = datetime.now(timezone.utc)
            if (not isinstance(approvals, tuple) or len(approvals) != 2
                    or any(not is_verified_approval(item) for item in approvals)):
                raise ExternalIntegrationError("provider write requires verifier-issued signed approvals")
            first, second = approvals
            artifact_binding = (
                first.artifact_id, first.artifact_version,
                first.artifact_sha256, first.artifact_size_bytes,
            )
            if (first.credential_schema != "RhemaScript.ApprovalCredential.v3"
                    or second.credential_schema != "RhemaScript.ApprovalCredential.v3"
                    or not first.subject_id or not second.subject_id
                    or first.subject_id == second.subject_id
                    or not first.actor_role or not second.actor_role
                    or not first.authn_context or not second.authn_context
                    or not first.identity_session_id or not second.identity_session_id
                    or not first.identity_policy_version
                    or first.identity_policy_version != second.identity_policy_version
                    or not first.identity_provider_id
                    or first.identity_provider_id != second.identity_provider_id
                    or first.authenticated_at is None or second.authenticated_at is None
                    or first.action != "FINAL_ACCEPTANCE" or second.action != "PUBLISH"
                    or first.actor_id == second.actor_id
                    or first.approval_id == second.approval_id
                    or first.issuer != second.issuer
                    or first.project_id != project_id or second.project_id != project_id
                    or first.project_version != source_version
                    or second.project_version != source_version
                    or first.request_id != request_id or second.request_id != request_id
                    or first.expires_at <= now or second.expires_at <= now
                    or any(value is None for value in artifact_binding)
                    or artifact_binding != (
                        second.artifact_id, second.artifact_version,
                        second.artifact_sha256, second.artifact_size_bytes,
                    )
                    or not isinstance(first.artifact_sha256, str)
                    or len(first.artifact_sha256) != 64
                    or any(ch not in "0123456789abcdef" for ch in first.artifact_sha256)
                    or not isinstance(first.artifact_size_bytes, int)
                    or isinstance(first.artifact_size_bytes, bool)
                    or first.artifact_size_bytes <= 0):
                raise ExternalIntegrationError("provider write approval scope, final-artifact binding or actor separation is invalid")
        elif authority_operation in self.CONSEQUENT_OPERATIONS:
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
            if event.get("phase") == "INDETERMINATE":
                if isinstance(exc, ExternalIntegrationError):
                    raise
                raise ExternalIntegrationError(
                    "provider write outcome is indeterminate; do not retry automatically until provider state is reconciled"
                ) from None
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
