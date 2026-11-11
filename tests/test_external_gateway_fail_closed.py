import unittest

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


if __name__ == "__main__":
    unittest.main()
