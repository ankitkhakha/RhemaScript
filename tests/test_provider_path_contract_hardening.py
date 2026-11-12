import unittest

from rhemascript.interfaces.external import (
    ExternalIntegrationError,
    ExternalIntegrationGateway,
    ProviderBinding,
)


class MethodTransport:
    def __init__(self):
        self.calls = []

    def send_request(self, url, method, headers, body, timeout):
        self.calls.append((url, method, headers, body))
        return 200, b"{}", {}


class ProviderPathContractHardeningTests(unittest.TestCase):
    def binding(self, *, hosts=("www.googleapis.com",), path_prefix="/youtube/v3/channels"):
        return ProviderBinding(
            interface_id="IF-18",
            provider_name="youtube",
            endpoint="https://www.googleapis.com",
            allowed_hosts=("www.googleapis.com",),
            operations={"CHANNEL_READ": {
                "method": "GET",
                "hosts": hosts,
                "path_prefix": path_prefix,
            }},
        )

    def gateway(self, binding):
        transport = MethodTransport()
        gateway = ExternalIntegrationGateway(
            (binding,), transport=transport, audit_sink=lambda event: None, enabled=True
        )
        return gateway, transport

    def request(self, url):
        return {
            "interface_id": "IF-18",
            "operation": "CHANNEL_READ",
            "url": url,
            "method": "GET",
            "request_id": "REQ-1",
            "project_id": "PROJECT-1",
            "source_version": "1.0",
        }

    def invoke(self, gateway, url):
        return gateway.request(
            "IF-18", "CHANNEL_READ", url,
            method="GET", request_id="REQ-1", project_id="PROJECT-1",
            source_version="1.0",
        )

    def test_method_contract_cannot_expand_parent_host_allowlist(self):
        with self.assertRaisesRegex(ExternalIntegrationError, "host exceeds binding allowlist"):
            self.binding(hosts=("attacker.example",)).validate()

    def test_method_contract_rejects_unsafe_literal_prefix(self):
        with self.assertRaisesRegex(ExternalIntegrationError, "invalid path prefix"):
            self.binding(path_prefix="/youtube/../admin").validate()

    def test_method_contract_rejects_encoded_traversal_prefix(self):
        with self.assertRaisesRegex(ExternalIntegrationError, "invalid path prefix"):
            self.binding(path_prefix="/youtube/%2e%2e/admin").validate()

    def test_method_contract_rejects_backslash_prefix(self):
        with self.assertRaisesRegex(ExternalIntegrationError, "invalid path prefix"):
            self.binding(path_prefix="/youtube\\admin").validate()

    def test_method_contract_rejects_backslash_in_host_allowlist(self):
        with self.assertRaisesRegex(ExternalIntegrationError, "host allowlist is invalid"):
            self.binding(hosts=("www.googleapis.com\\\\",)).validate()

    def test_method_contract_rejects_invalid_method(self):
        binding = self.binding()
        binding.operations["CHANNEL_READ"]["method"] = "TRACE"
        with self.assertRaisesRegex(ExternalIntegrationError, "invalid HTTP method"):
            binding.validate()

    def test_request_rejects_literal_and_encoded_dot_segments(self):
        gateway, transport = self.gateway(self.binding())
        for suffix in ("/../videos", "/%2e%2e/videos", "/%2E%2E/videos"):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ExternalIntegrationError, "outside the provider operation allowlist"):
                    self.invoke(gateway, "https://www.googleapis.com/youtube/v3/channels" + suffix)
        self.assertEqual(transport.calls, [])

    def test_request_rejects_encoded_backslash_and_null(self):
        gateway, transport = self.gateway(self.binding())
        for suffix in ("/%5c..%5cadmin", "/%00admin"):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ExternalIntegrationError, "outside the provider operation allowlist"):
                    self.invoke(gateway, "https://www.googleapis.com/youtube/v3/channels" + suffix)
        self.assertEqual(transport.calls, [])

    def test_request_rejects_double_encoded_traversal(self):
        gateway, transport = self.gateway(self.binding())
        url = "https://www.googleapis.com/youtube/v3/channels/%252e%252e/admin"
        with self.assertRaisesRegex(ExternalIntegrationError, "outside the provider operation allowlist"):
            self.invoke(gateway, url)
        self.assertEqual(transport.calls, [])

    def test_request_rejects_path_prefix_sibling(self):
        gateway, transport = self.gateway(self.binding())
        with self.assertRaisesRegex(ExternalIntegrationError, "outside the provider operation allowlist"):
            self.invoke(gateway, "https://www.googleapis.com/youtube/v3/channelsEvil")
        self.assertEqual(transport.calls, [])

    def test_valid_encoded_path_within_prefix_is_allowed(self):
        gateway, transport = self.gateway(self.binding())
        result = self.invoke(gateway, "https://www.googleapis.com/youtube/v3/channels/channel%2Did")
        self.assertEqual(result[0], 200)
        self.assertEqual(len(transport.calls), 1)

    def test_method_contract_rejects_non_finite_timeout(self):
        binding = self.binding()
        object.__setattr__(binding, "timeout_seconds", float("nan"))
        with self.assertRaisesRegex(ExternalIntegrationError, "timeout must be finite"):
            binding.validate()


if __name__ == "__main__":
    unittest.main()
