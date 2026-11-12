import unittest

from rhemascript.interfaces.contracts import (
    InterfaceContractError,
    validate_interface_request,
)
from rhemascript.interfaces.runtime import InterfaceError, InterfaceGateway


def request(**overrides):
    value = {
        "request_id": "REQ-001",
        "project_id": "RS-SYNTHETIC-001",
        "operation": "ASSESS",
        "payload": {"sample": True},
        "source_version": "1.0",
    }
    value.update(overrides)
    return value


class InterfaceContractTests(unittest.TestCase):
    def test_registered_interface_accepts_common_envelope(self):
        fingerprint = validate_interface_request("IF-01", request())
        self.assertEqual(len(fingerprint), 64)

    def test_fingerprint_is_independent_of_object_key_order(self):
        first = request()
        second = dict(reversed(list(first.items())))
        self.assertEqual(
            validate_interface_request("IF-01", first),
            validate_interface_request("IF-01", second),
        )

    def test_unknown_interface_is_rejected(self):
        with self.assertRaises(InterfaceContractError):
            validate_interface_request("IF-99", request())

    def test_unhashable_interface_identifier_is_rejected_cleanly(self):
        with self.assertRaises(InterfaceContractError):
            validate_interface_request([], request())
        with self.assertRaises(InterfaceError):
            InterfaceGateway().invoke([], request())

    def test_missing_required_field_is_rejected(self):
        value = request()
        del value["source_version"]
        with self.assertRaises(InterfaceContractError):
            validate_interface_request("IF-01", value)

    def test_blank_identifiers_are_rejected(self):
        with self.assertRaises(InterfaceContractError):
            validate_interface_request("IF-01", request(project_id=" "))

    def test_non_object_payload_is_rejected(self):
        with self.assertRaises(InterfaceContractError):
            validate_interface_request("IF-01", request(payload=[]))

    def test_non_json_payload_is_rejected(self):
        with self.assertRaises(InterfaceContractError):
            validate_interface_request("IF-01", request(payload={"bad": object()}))

    def test_non_string_interface_identifier_is_rejected_cleanly(self):
        with self.assertRaises(InterfaceContractError):
            validate_interface_request([], request())

    def test_non_string_nested_object_keys_are_rejected(self):
        with self.assertRaisesRegex(InterfaceContractError, "keys must be strings"):
            validate_interface_request("IF-01", request(payload={1: "ambiguous"}))

    def test_python_tuple_is_not_accepted_as_json_array(self):
        with self.assertRaisesRegex(InterfaceContractError, "JSON-compatible"):
            validate_interface_request("IF-01", request(payload={"values": (1, 2)}))

    def test_nan_is_rejected(self):
        with self.assertRaises(InterfaceContractError):
            validate_interface_request("IF-01", request(payload={"bad": float("nan")}))

    def test_gateway_uses_shared_contract(self):
        gateway = InterfaceGateway()
        response = gateway.invoke("IF-01", request())
        self.assertEqual(response.status, "ACCEPTED_FOR_LOCAL_PROCESSING")
        with self.assertRaises(InterfaceError):
            gateway.invoke("IF-01", request(operation=" "))

    def test_generic_gateway_acknowledges_but_does_not_dispatch_read_operations(self):
        response = InterfaceGateway().invoke(
            "IF-01",
            request(operation="READ_LEARNING_UNIT"),
        )
        self.assertEqual(response.status, "ACCEPTED_FOR_LOCAL_PROCESSING")
        self.assertNotEqual(response.status, "COMPLETED_READ_ONLY")

    def test_gateway_replays_identical_request_with_same_key(self):
        gateway = InterfaceGateway()
        first = gateway.invoke("IF-01", request())
        second = gateway.invoke("IF-01", request())
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(first.idempotency_key, second.idempotency_key)

    def test_replay_cache_is_namespaced_by_interface(self):
        gateway = InterfaceGateway()
        first = gateway.invoke("IF-01", request())
        second = gateway.invoke("IF-02", request())
        self.assertEqual(first.request_id, second.request_id)
        self.assertEqual(first.idempotency_key, second.idempotency_key)
        self.assertEqual(first.interface_id, "IF-01")
        self.assertEqual(second.interface_id, "IF-02")

    def test_malformed_authority_container_is_rejected_cleanly(self):
        gateway = InterfaceGateway()
        with self.assertRaises(InterfaceError):
            gateway.invoke("IF-01", request(operation="GENERATE"), authority=[])


    def test_whitespace_and_case_do_not_bypass_consequential_authority(self):
        required = {
            "GENERATE": "generation_authorisation",
            "PUBLISH": "publishing_authorisation",
            "SPEND": "spending_authorisation",
            "EXTERNAL_WRITE": "external_action_authorisation",
        }
        for operation, authority_key in required.items():
            with self.subTest(operation=operation):
                gateway = InterfaceGateway()
                with self.assertRaises(InterfaceError):
                    gateway.invoke(
                        "IF-01",
                        request(operation=f"  {operation.lower()}  "),
                    )
                with self.assertRaises(InterfaceError):
                    gateway.invoke(
                        "IF-01",
                        request(operation=f" {operation} "),
                        authority={authority_key: False},
                    )

    def test_consequential_action_requires_exact_true_authority(self):
        gateway = InterfaceGateway()
        with self.assertRaises(InterfaceError):
            gateway.invoke(
                "IF-01",
                request(operation="GENERATE"),
                authority={"generation_authorisation": 1},
            )

    def test_caller_mutation_cannot_change_cached_request_or_response(self):
        gateway = InterfaceGateway()
        original = request(payload={"nested": {"value": "accepted"}})
        first = gateway.invoke("IF-01", original)
        original["payload"]["nested"]["value"] = "caller-mutated"
        first.payload["payload"]["nested"]["value"] = "response-mutated"

        replay = gateway.invoke(
            "IF-01",
            request(payload={"nested": {"value": "accepted"}}),
        )
        self.assertEqual(
            replay.payload["payload"]["nested"]["value"], "accepted"
        )
        self.assertIsNot(replay, first)
        self.assertIsNot(replay.payload, first.payload)


if __name__ == "__main__":
    unittest.main()
