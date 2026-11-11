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

    def test_nan_is_rejected(self):
        with self.assertRaises(InterfaceContractError):
            validate_interface_request("IF-01", request(payload={"bad": float("nan")}))

    def test_gateway_uses_shared_contract(self):
        gateway = InterfaceGateway()
        response = gateway.invoke("IF-01", request())
        self.assertEqual(response.status, "ACCEPTED_FOR_LOCAL_PROCESSING")
        with self.assertRaises(InterfaceError):
            gateway.invoke("IF-01", request(operation=" "))

    def test_gateway_replays_identical_request_with_same_key(self):
        gateway = InterfaceGateway()
        first = gateway.invoke("IF-01", request())
        second = gateway.invoke("IF-01", request())
        self.assertIs(first, second)
        self.assertEqual(first.idempotency_key, second.idempotency_key)


    def test_whitespace_and_case_do_not_bypass_generation_authority(self):
        gateway = InterfaceGateway()
        with self.assertRaises(InterfaceError):
            gateway.invoke("IF-01", request(operation="  gEnErAtE  "))

    def test_explicit_generation_authority_is_required_even_with_whitespace(self):
        gateway = InterfaceGateway()
        with self.assertRaises(InterfaceError):
            gateway.invoke(
                "IF-01",
                request(operation=" GENERATE "),
                authority={"generation_authorisation": False},
            )


if __name__ == "__main__":
    unittest.main()
