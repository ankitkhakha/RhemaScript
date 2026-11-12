"""Contract tests for the local RAEI read-only endpoint."""
import tempfile
import unittest
from pathlib import Path

from raei.interface_adapter import RAEIReadOnlyAdapter
from raei.store import EvidenceStore
from rhemascript.interfaces.raei_endpoint import RAEIEndpointError, RAEIReadOnlyEndpoint


class RAEIReadOnlyEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(Path(self.temp.name) / "endpoint.sqlite")
        self.store.create_unit("UNIT-ENDPOINT", "Endpoint fixture")
        self.endpoint = RAEIReadOnlyEndpoint(RAEIReadOnlyAdapter(self.store))

    def tearDown(self):
        self.temp.cleanup()

    def request(self, **overrides):
        value = {
            "request_id": "REQ-RAEI-001",
            "project_id": "RS-SYNTHETIC-001",
            "operation": "READ_LEARNING_UNIT",
            "payload": {"unit_id": "UNIT-ENDPOINT"},
            "source_version": "1.0",
        }
        value.update(overrides)
        return value

    def test_read_request_completes_locally_without_write_or_provider_call(self):
        result = self.endpoint.invoke(self.request())
        self.assertEqual(result["status"], "COMPLETED_READ_ONLY")
        self.assertFalse(result["write_performed"])
        self.assertFalse(result["provider_call_performed"])
        self.assertEqual(result["result"]["result"]["unit"]["unit_id"], "UNIT-ENDPOINT")

    def test_unknown_or_write_operation_is_rejected(self):
        for operation in ("PUBLISH", "GENERATE", "RECORD_LEARNING_ASSESSMENT", "UNKNOWN"):
            with self.subTest(operation=operation):
                with self.assertRaises(RAEIEndpointError):
                    self.endpoint.invoke(self.request(operation=operation, payload={}))

    def test_extra_and_missing_envelope_fields_are_rejected(self):
        with self.assertRaises(RAEIEndpointError):
            self.endpoint.invoke(self.request(unreviewed_authority=True))
        request = self.request()
        del request["source_version"]
        with self.assertRaises(RAEIEndpointError):
            self.endpoint.invoke(request)

    def test_non_json_payload_is_rejected(self):
        with self.assertRaisesRegex(RAEIEndpointError, "finite JSON"):
            self.endpoint.invoke(self.request(payload={"value": float("nan")}))

    def test_disclosure_denial_prevents_dispatch(self):
        with self.assertRaisesRegex(RAEIEndpointError, "disclosure denied"):
            self.endpoint.invoke(self.request(), task_need=False)

    def test_invalid_envelope_identity_is_rejected(self):
        with self.assertRaises(RAEIEndpointError):
            self.endpoint.invoke(self.request(request_id=" "))


if __name__ == "__main__":
    unittest.main()
