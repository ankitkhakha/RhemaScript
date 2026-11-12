import unittest
from unittest.mock import patch

from rhemascript.interfaces.external import (
    ExternalIntegrationError,
    ExternalIntegrationGateway,
    ProviderBinding,
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

    def test_method_aware_binding_cannot_expand_host_allowlist(self):
        transport = NeverTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"CHANNEL_READ": {
                "method": "GET", "hosts": ("attacker.example",),
                "path_prefix": "/youtube/v3/channels",
            }},
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "host exceeds binding allowlist"):
            ExternalIntegrationGateway(
                (binding,), transport=transport,
                audit_sink=lambda event: None, enabled=True,
            )
        self.assertEqual(transport.calls, [])

    def test_method_aware_binding_rejects_unsafe_path_prefix(self):
        transport = NeverTransport()
        binding = ProviderBinding(
            interface_id="IF-18", provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"CHANNEL_READ": {
                "method": "GET", "hosts": ("www.googleapis.com",),
                "path_prefix": "/youtube/../admin",
            }},
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "invalid path prefix"):
            ExternalIntegrationGateway(
                (binding,), transport=transport,
                audit_sink=lambda event: None, enabled=True,
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
        with self.assertRaisesRegex(ExternalIntegrationError, "explicit authority"):
            gateway.request(
                "IF-18", "UPLOAD_CHUNK",
                "https://www.googleapis.com/upload/youtube/v3/videos/session",
                **args,
            )
        self.assertEqual(transport.calls, [])

    def test_upload_chunk_with_publish_authority_preserves_308_acknowledgement(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, headers, body))
                return 308, b"", {"Range": "bytes=0-127"}

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
        with patch("rhemascript.core.authority.authorise_action", return_value=True):
            status, body, response_headers = gateway.request(
                "IF-18", "UPLOAD_CHUNK",
                "https://www.googleapis.com/upload/youtube/v3/videos/session",
                method="PUT", headers={"Authorization": "Bearer test"},
                body=b"chunk", request_id="upload-2", project_id="RS-1",
                source_version="1.0",
                authority={"publishing_authorisation": True},
            )
        self.assertEqual(status, 308)
        self.assertEqual(body, b"")
        self.assertEqual(response_headers["Range"], "bytes=0-127")
        self.assertEqual(transport.calls[0][1], "PUT")

    def test_method_aware_request_audits_and_preserves_response_headers(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, headers, body))
                return 308, b"", {"Range": "bytes=0-9"}

        events = []
        transport = MethodTransport()
        gateway = ExternalIntegrationGateway(
            (ProviderBinding(
                interface_id="IF-18", provider_name="youtube",
                endpoint="https://www.googleapis.com",
                allowed_hosts=("www.googleapis.com",),
                operations={"UPLOAD_CHUNK": {
                    "method": "PUT", "hosts": ("www.googleapis.com",),
                    "path_prefix": "/upload/youtube/v3/videos",
                }},
            ),), transport=transport, audit_sink=events.append, enabled=True,
        )
        status, body, response_headers = gateway.request(
            "IF-18", "UPLOAD_CHUNK",
            "https://www.googleapis.com/upload/youtube/v3/videos?upload_id=opaque",
            method="PUT", headers={"Authorization": "Bearer secret"},
            body=b"video bytes", request_id="r1", project_id="p1", source_version="1",
            authority={"publishing_authorisation": True},
        )
        self.assertEqual(status, 308)
        self.assertEqual(body, b"")
        self.assertEqual(response_headers["Range"], "bytes=0-9")
        self.assertEqual(transport.calls[0][1], "PUT")
        self.assertEqual([event["phase"] for event in events], ["REQUESTED", "COMPLETED"])
        self.assertNotIn("secret", repr(events))
        self.assertNotIn("opaque", repr(events))
        self.assertNotIn("video bytes", repr(events))


if __name__ == "__main__":
    unittest.main()
