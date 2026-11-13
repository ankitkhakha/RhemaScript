import unittest
import threading
import json
import hashlib
import os
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from rhemascript.core.approvals import ApprovalVerifier
from rhemascript.core.approval_store import SQLitePublishSessionRegistry
from rhemascript.integrations.session_url_vault import (
    SQLiteEncryptedSessionUrlVault, publish_session_vault_reference,
)

from rhemascript.interfaces.external import (
    ExternalIntegrationError,
    ExternalIntegrationGateway,
    ProviderBinding,
    _publish_approval_fingerprint,
)


class NeverTransport:
    def __init__(self):
        self.calls = []

    def send(self, url, headers, body, timeout):
        self.calls.append((url, headers, body, timeout))
        return 200, b'{"ok":true}'


class ExternalGatewayFailClosedTests(unittest.TestCase):
    def binding(self, interface_id="IF-01"):
        return ProviderBinding(
            interface_id=interface_id,
            provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"READ": "youtube/v3/channels"},
        )

    def request(self):
        return {
            "request_id": "test-request-1",
            "project_id": "RS-TEST-001",
            "operation": "READ",
            "payload": {},
            "source_version": "1.0",
        }


    def publish_authority(self, request_id, project_id="RS-1", source_version="1.0", identity_overrides=None, verification_time=None):
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        now = verification_time or datetime.now(timezone.utc)
        binding = {
            "artifact_id": "ART-FINAL-001",
            "artifact_version": "1",
            "sha256": "a" * 64,
            "size_bytes": 123456,
        }
        credentials = []
        for action, actor, suffix in (
            ("FINAL_ACCEPTANCE", "director-001", "final"),
            ("PUBLISH", "publisher-001", "publish"),
        ):
            payload = {
                "schema": "RhemaScript.ApprovalCredential.v3",
                "approval_id": f"approval-{suffix}-{request_id}",
                "issuer": "RhemaScript-Approval-Service",
                "actor_id": actor,
                "action": action,
                "project_id": project_id,
                "project_version": source_version,
                "request_id": request_id,
                "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(minutes=10)).isoformat(),
                "nonce": f"nonce-{suffix}-{request_id}",
                "key_id": "key-2026-01",
                "artifact_id": binding["artifact_id"],
                "artifact_version": binding["artifact_version"],
                "artifact_sha256": binding["sha256"],
                "artifact_size_bytes": binding["size_bytes"],
                "subject_id": "subject-" + actor,
                "actor_role": "director" if action == "FINAL_ACCEPTANCE" else "publisher",
                "authn_context": "mfa",
                "authenticated_at": now.isoformat(),
                "identity_session_id": "session-" + actor,
                "identity_policy_version": "identity-policy-v1",
                "identity_provider_id": "test-idp",
            }
            payload.update((identity_overrides or {}).get(action, {}))
            payload["signature"] = private_key.sign(
                json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode()
            ).hex()
            credentials.append(payload)
        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=lambda entries: True,
            clock=lambda: now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {
                    "FINAL_ACCEPTANCE": ["director"],
                    "PUBLISH": ["publisher"],
                },
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )
        expectations = tuple({
            "action": action, "project_id": project_id,
            "project_version": source_version, "request_id": request_id,
            "artifact_binding": binding,
        } for action in ("FINAL_ACCEPTANCE", "PUBLISH"))
        verified = verifier.verify_many_and_consume(tuple(credentials), expectations)
        return {"verified_approvals": verified}

    def make_registry(self, authority, request_id, session_url=None):
        temporary = tempfile.TemporaryDirectory()
        os.chmod(temporary.name, 0o700)
        registry = SQLitePublishSessionRegistry(Path(temporary.name) / "publish.sqlite3")
        vault = SQLiteEncryptedSessionUrlVault(
            Path(temporary.name) / "session-url-vault.sqlite3", b"v" * 32,
        )
        approvals = authority["verified_approvals"]
        first = approvals[0]
        identity = {
            "project_id": first.project_id,
            "project_version": first.project_version,
            "request_id": request_id,
            "approval_fingerprint": _publish_approval_fingerprint(approvals),
            "artifact_id": first.artifact_id,
            "artifact_version": first.artifact_version,
            "artifact_sha256": first.artifact_sha256,
            "artifact_size_bytes": first.artifact_size_bytes,
        }
        if session_url is not None:
            vault.store(publish_session_vault_reference(identity), session_url)
            owner = "registry-setup"
            self.assertTrue(registry.reserve_publish_session(
                **identity, owner_id=owner, lease_seconds=60,
            ))
            self.assertTrue(registry.bind_publish_session(
                **identity,
                session_url_sha256=hashlib.sha256(session_url.encode()).hexdigest(),
                owner_id=owner,
            ))
            self.assertTrue(registry.finalize_publish_session_operation(
                project_id=first.project_id, project_version=first.project_version,
                request_id=request_id, owner_id=owner,
            ))
        return temporary, registry, vault

    def test_gateway_disabled_by_default_and_fails_before_transport(self):
        transport = NeverTransport()
        gateway = ExternalIntegrationGateway(
            (self.binding(),), transport=transport, audit_sink=lambda event: None
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "disabled"):
            gateway.invoke("IF-01", self.request())
        self.assertEqual(transport.calls, [])

    def test_unknown_interface_mapping_fails_before_transport(self):
        transport = NeverTransport()
        gateway = ExternalIntegrationGateway(
            (self.binding("IF-99"),), transport=transport,
            audit_sink=lambda event: None, enabled=True,
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "unknown interface"):
            gateway.invoke("IF-99", self.request())
        self.assertEqual(transport.calls, [])

    def test_missing_audit_sink_fails_before_transport(self):
        transport = NeverTransport()
        gateway = ExternalIntegrationGateway(
            (self.binding(),), transport=transport, enabled=True
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "audit sink"):
            gateway.invoke("IF-01", self.request())
        self.assertEqual(transport.calls, [])

    def test_missing_provider_binding_fails_before_transport(self):
        transport = NeverTransport()
        gateway = ExternalIntegrationGateway(
            (), transport=transport, audit_sink=lambda event: None, enabled=True
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "no provider contract"):
            gateway.invoke("IF-01", self.request())
        self.assertEqual(transport.calls, [])

    def test_method_aware_request_requires_exact_operation_contract(self):
        transport = NeverTransport()
        gateway = ExternalIntegrationGateway(
            (ProviderBinding(
                interface_id="IF-18", provider_name="youtube",
                endpoint="https://www.googleapis.com",
                allowed_hosts=("www.googleapis.com", "oauth2.googleapis.com"),
                operations={"CHANNEL_READ": {
                    "method": "GET", "hosts": ("www.googleapis.com",),
                    "path_prefix": "/youtube/v3/channels",
                }},
            ),), transport=transport, audit_sink=lambda event: None, enabled=True,
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "method is not permitted"):
            gateway.request(
                "IF-18", "CHANNEL_READ", "https://www.googleapis.com/youtube/v3/channels?mine=true",
                method="POST", request_id="r1", project_id="p1", source_version="1",
            )
        self.assertEqual(transport.calls, [])

    def test_method_aware_request_rejects_path_prefix_sibling(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append(url)
                return 200, b"{}", {}

        transport = MethodTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"CHANNEL_READ": {
                "method": "GET", "hosts": ("www.googleapis.com",),
                "path_prefix": "/youtube/v3/channels",
            }},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=lambda event: None, enabled=True,
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "outside the provider operation allowlist"):
            gateway.request(
                "IF-18", "CHANNEL_READ",
                "https://www.googleapis.com/youtube/v3/channelsEvil?mine=true",
                method="GET", request_id="r1", project_id="p1", source_version="1",
            )
        self.assertEqual(transport.calls, [])

    def test_gateway_denies_valid_upload_without_durable_registry_before_transport(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, headers, body))
                return 200, b'{"id":"unexpected"}', {}

        transport = MethodTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"UPLOAD_SESSION": {
                "method": "POST", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/videos",
            }},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=lambda event: None, enabled=True,
        )
        authority = self.publish_authority("upload-no-registry")
        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            with self.assertRaisesRegex(ExternalIntegrationError, "durable SQLitePublishSessionRegistry"):
                gateway.request(
                    "IF-18", "UPLOAD_SESSION",
                    "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable",
                    method="POST", body=b"metadata", request_id="upload-no-registry",
                    project_id="RS-1", source_version="1.0", authority=authority,
                )
        self.assertEqual(transport.calls, [])

    def test_upload_chunk_requires_separate_publish_authority_before_transport(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, headers, body))
                return 308, b"", {"Range": "bytes=0-9"}

        transport = MethodTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"UPLOAD_CHUNK": {
                "method": "PUT", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/videos",
            }},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=lambda event: None, enabled=True,
        )
        args = {
            "method": "PUT", "headers": {"Authorization": "Bearer test"},
            "body": b"chunk", "request_id": "upload-1", "project_id": "RS-1",
            "source_version": "1.0",
        }
        with self.assertRaisesRegex(ExternalIntegrationError, "verifier-issued signed approvals"):
            gateway.request(
                "IF-18", "UPLOAD_CHUNK",
                "https://www.googleapis.com/upload/youtube/v3/videos/session",
                **args,
            )
        self.assertEqual(transport.calls, [])

    def test_provider_write_rejects_same_underlying_subject_before_transport(self):
        transport = NeverTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"UPLOAD_CHUNK": {
                "method": "PUT", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/videos",
            }},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=lambda event: None, enabled=True,
        )
        authority = self.publish_authority(
            "same-subject",
            identity_overrides={
                "FINAL_ACCEPTANCE": {"subject_id": "same-human-subject-0001"},
                "PUBLISH": {"subject_id": "same-human-subject-0001"},
            },
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "actor separation"):
            gateway.request(
                "IF-18", "UPLOAD_CHUNK",
                "https://www.googleapis.com/upload/youtube/v3/videos/session",
                method="PUT", headers={"Authorization": "Bearer test"},
                body=b"chunk", request_id="same-subject", project_id="RS-1",
                source_version="1.0", authority=authority,
            )
        self.assertEqual(transport.calls, [])

    def test_provider_write_rejects_shared_identity_session_before_transport(self):
        transport = NeverTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"UPLOAD_CHUNK": {
                "method": "PUT", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/videos",
            }},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=lambda event: None, enabled=True,
        )
        authority = self.publish_authority(
            "shared-session",
            identity_overrides={
                "FINAL_ACCEPTANCE": {"identity_session_id": "shared-session-0001"},
                "PUBLISH": {"identity_session_id": "shared-session-0001"},
            },
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "actor separation"):
            gateway.request(
                "IF-18", "UPLOAD_CHUNK",
                "https://www.googleapis.com/upload/youtube/v3/videos/session",
                method="PUT", headers={"Authorization": "Bearer test"},
                body=b"chunk", request_id="shared-session", project_id="RS-1",
                source_version="1.0", authority=authority,
            )
        self.assertEqual(transport.calls, [])

    def test_provider_write_rechecks_authentication_freshness_at_use_time(self):
        from datetime import datetime, timedelta, timezone
        transport = NeverTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"UPLOAD_CHUNK": {
                "method": "PUT", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/videos",
            }},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=lambda event: None, enabled=True,
        )
        verified_at = datetime.now(timezone.utc) - timedelta(minutes=6)
        authority = self.publish_authority("stale-at-write", verification_time=verified_at)
        with self.assertRaisesRegex(ExternalIntegrationError, "actor separation"):
            gateway.request(
                "IF-18", "UPLOAD_CHUNK",
                "https://www.googleapis.com/upload/youtube/v3/videos/session",
                method="PUT", headers={"Authorization": "Bearer test"},
                body=b"chunk", request_id="stale-at-write", project_id="RS-1",
                source_version="1.0", authority=authority,
            )
        self.assertEqual(transport.calls, [])

    def test_upload_chunk_with_publish_authority_preserves_308_acknowledgement(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, headers, body))
                return 308, b"", {"Range": "bytes=0-4"}

        transport = MethodTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"UPLOAD_CHUNK": {
                "method": "PUT", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/videos",
            }},
        )
        authority = self.publish_authority("upload-2")
        session_url = "https://www.googleapis.com/upload/youtube/v3/videos/session?upload_id=session-opaque"
        temporary, registry, vault = self.make_registry(authority, "upload-2", session_url=session_url)
        self.addCleanup(temporary.cleanup)
        events = []
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=events.append,
            publish_session_registry=registry, session_url_vault=vault, enabled=True,
        )
        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            status, body, response_headers = gateway.request(
                "IF-18", "UPLOAD_CHUNK", session_url,
                method="PUT",
                headers={"Authorization": "Bearer test", "Content-Range": "bytes 0-4/123456",
                         "Content-Length": "5"},
                body=b"chunk", request_id="upload-2", project_id="RS-1",
                source_version="1.0", authority=authority,
            )
        self.assertEqual(status, 308)
        self.assertEqual(body, b"")
        self.assertEqual(response_headers["Range"], "bytes=0-4")
        self.assertEqual(transport.calls[0][1], "PUT")
        self.assertEqual(
            events[-1]["session_url_sha256"],
            hashlib.sha256(session_url.encode()).hexdigest(),
        )
        self.assertEqual(events[-1]["acknowledged_offset"], 5)
        self.assertEqual(events[-1]["publish_session_state"], "ACTIVE")
        self.assertNotIn("upload_id=session-opaque", repr(events))

    def test_write_transport_failure_is_reported_as_indeterminate_not_failed(self):
        class AmbiguousTransport:
            def send_request(self, url, method, headers, body, timeout):
                raise TimeoutError("connection lost after request may have reached provider")

        events = []
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"UPLOAD_SESSION": {
                "method": "POST", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/videos",
            }},
        )
        authority = self.publish_authority("write-1")
        temporary, registry, vault = self.make_registry(authority, "write-1")
        self.addCleanup(temporary.cleanup)
        gateway = ExternalIntegrationGateway(
            (binding,), transport=AmbiguousTransport(),
            audit_sink=events.append, publish_session_registry=registry, session_url_vault=vault, enabled=True,
        )
        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            with self.assertRaisesRegex(ExternalIntegrationError, "indeterminate.*do not retry automatically"):
                gateway.request(
                    "IF-18", "UPLOAD_SESSION",
                    "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable",
                    method="POST", body=b"metadata", request_id="write-1",
                    project_id="RS-1", source_version="1.0", authority=authority,
                )
        self.assertIn("INDETERMINATE", [event["phase"] for event in events])
        state = registry.get_publish_session(project_id="RS-1", project_version="1.0", request_id="write-1")
        self.assertEqual(state["state"], "INDETERMINATE")
        self.assertNotIn("FAILED", [event["phase"] for event in events])

    def test_thumbnail_write_is_blocked_at_gateway_before_transport(self):
        transport = NeverTransport()
        binding = ProviderBinding(
            interface_id="IF-18",
            provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"THUMBNAIL_WRITE": {
                "method": "POST", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/thumbnails/set",
            }},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=lambda event: None, enabled=True,
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
            gateway.request(
                "IF-18", "THUMBNAIL_WRITE",
                "https://www.googleapis.com/upload/youtube/v3/thumbnails/set?videoId=video-123",
                method="POST", body=b"thumbnail", request_id="thumb-request-1",
                project_id="RS-1", source_version="1.0",
            )
        self.assertEqual(transport.calls, [])

    def test_write_completion_audit_failure_is_indeterminate(self):
        class SuccessTransport:
            def send_request(self, url, method, headers, body, timeout):
                return 200, b'{"session":"created"}', {"Location": "https://www.googleapis.com/upload/youtube/v3/videos/session?upload_id=opaque"}

        events = []
        def audit(event):
            events.append(dict(event))
            if event["phase"] == "COMPLETED":
                raise OSError("audit storage unavailable")

        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"UPLOAD_SESSION": {
                "method": "POST", "hosts": ("www.googleapis.com",),
                "path_prefix": "/upload/youtube/v3/videos",
            }},
        )
        authority = self.publish_authority("write-2")
        temporary, registry, vault = self.make_registry(authority, "write-2")
        self.addCleanup(temporary.cleanup)
        gateway = ExternalIntegrationGateway(
            (binding,), transport=SuccessTransport(), audit_sink=audit,
            publish_session_registry=registry, session_url_vault=vault, enabled=True,
        )
        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            with self.assertRaisesRegex(ExternalIntegrationError, "indeterminate.*do not retry automatically"):
                gateway.request(
                    "IF-18", "UPLOAD_SESSION",
                    "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable",
                    method="POST", body=b"metadata", request_id="write-2",
                    project_id="RS-1", source_version="1.0", authority=authority,
                )
        self.assertIn("INDETERMINATE", [event["phase"] for event in events])
        state = registry.get_publish_session(project_id="RS-1", project_version="1.0", request_id="write-2")
        self.assertEqual(state["state"], "INDETERMINATE")
        self.assertIsNotNone(state["session_url_sha256"])

    def test_method_aware_request_audits_and_preserves_response_headers(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, headers, body))
                return 308, b"", {"Range": "bytes=0-9"}

        events = []
        transport = MethodTransport()
        authority = self.publish_authority("request-3", project_id="project-1", source_version="1.0")
        session_url = "https://www.googleapis.com/upload/youtube/v3/videos?upload_id=opaque"
        temporary, registry, vault = self.make_registry(authority, "request-3", session_url=session_url)
        self.addCleanup(temporary.cleanup)
        gateway = ExternalIntegrationGateway(
            (ProviderBinding(
                interface_id="IF-18", provider_name="youtube",
                endpoint="https://www.googleapis.com",
                allowed_hosts=("www.googleapis.com",),
                operations={"UPLOAD_CHUNK": {
                    "method": "PUT", "hosts": ("www.googleapis.com",),
                    "path_prefix": "/upload/youtube/v3/videos",
                }},
            ),), transport=transport, audit_sink=events.append,
            publish_session_registry=registry, session_url_vault=vault, enabled=True,
        )
        status, body, response_headers = gateway.request(
            "IF-18", "UPLOAD_CHUNK", session_url,
            method="PUT",
            headers={"Authorization": "Bearer secret", "Content-Range": "bytes 0-10/123456",
                     "Content-Length": "11"},
            body=b"video bytes", request_id="request-3", project_id="project-1", source_version="1.0",
            authority=authority,
        )
        self.assertEqual(status, 308)
        self.assertEqual(body, b"")
        self.assertEqual(response_headers["Range"], "bytes=0-9")
        self.assertEqual(transport.calls[0][1], "PUT")
        self.assertEqual([event["phase"] for event in events], ["REQUESTED", "COMPLETED"])
        self.assertNotIn("secret", repr(events))
        self.assertNotIn("opaque", repr(events))
        self.assertNotIn("video bytes", repr(events))

    def test_generic_post_invocation_requires_external_write_authority(self):
        transport = NeverTransport()
        gateway = ExternalIntegrationGateway(
            (self.binding(),), transport=transport,
            audit_sink=lambda event: None, enabled=True,
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "external-write authority"):
            gateway.invoke("IF-01", self.request())
        self.assertEqual(transport.calls, [])

    def test_generic_post_invocation_requires_explicit_authority_before_transport(self):
        transport = NeverTransport()
        gateway = ExternalIntegrationGateway(
            (self.binding(),), transport=transport,
            audit_sink=lambda event: None, enabled=True,
        )
        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            result = gateway.invoke("IF-01", self.request())
        self.assertEqual(result["status"], "PROVIDER_CONFIRMED")
        self.assertEqual(len(transport.calls), 1)

    def test_generic_operation_path_rejects_traversal_before_transport(self):
        transport = NeverTransport()
        binding = ProviderBinding(
            interface_id="IF-01", provider_name="provider",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"READ": "../admin"},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport,
            audit_sink=lambda event: None, enabled=True,
        )
        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            with self.assertRaisesRegex(ExternalIntegrationError, "safe relative provider path"):
                gateway.invoke("IF-01", self.request())
        self.assertEqual(transport.calls, [])

    def test_generic_operation_path_rejects_encoded_traversal_before_transport(self):
        transport = NeverTransport()
        binding = ProviderBinding(
            interface_id="IF-01", provider_name="provider",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"READ": "youtube/%2e%2e/admin"},
        )
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport,
            audit_sink=lambda event: None, enabled=True,
        )
        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            with self.assertRaisesRegex(ExternalIntegrationError, "safe relative provider path"):
                gateway.invoke("IF-01", self.request())
        self.assertEqual(transport.calls, [])


    def test_concurrent_duplicate_invocations_share_one_provider_post(self):
        entered = threading.Event()
        release = threading.Event()
        class BlockingTransport:
            def __init__(self):
                self.calls = 0
            def send(self, url, headers, body, timeout):
                self.calls += 1
                entered.set()
                if not release.wait(3):
                    raise RuntimeError("test transport timed out")
                return 200, b'{"ok":true}'

        transport = BlockingTransport()
        gateway = ExternalIntegrationGateway(
            (self.binding(),), transport=transport,
            audit_sink=lambda event: None, enabled=True,
        )
        results, errors = [], []
        def invoke():
            try:
                results.append(gateway.invoke(
                    "IF-01", self.request(),
                    authority={"external_action_authorisation": True},
                ))
            except Exception as exc:
                errors.append(exc)

        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            first = threading.Thread(target=invoke)
            second = threading.Thread(target=invoke)
            first.start()
            self.assertTrue(entered.wait(2))
            second.start()
            release.set()
            first.join(3)
            second.join(3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(transport.calls, 1)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])


if __name__ == "__main__":
    unittest.main()
