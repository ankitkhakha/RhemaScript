import json
import unittest
from rhemascript.interfaces.external import (
    ExternalIntegrationError, ExternalIntegrationGateway, ProviderBinding
)
from rhemascript.assurance import assess_production_readiness

class FakeTransport:
    def __init__(self, status=200, body=b'{"accepted":true}'):
        self.status, self.body, self.calls = status, body, []
    def send(self, url, headers, body, timeout):
        self.calls.append((url, headers, body, timeout))
        return self.status, self.body

def binding():
    return ProviderBinding("IF-01", "mock-provider", "https://api.example.test/v1",
                           ("api.example.test",), {"VALIDATE": "validate", "EXTERNAL_WRITE": "write"})

def request(op="VALIDATE"):
    return {"request_id":"req-1","project_id":"project-1","operation":op,
            "payload":{"sample":True},"source_version":"test-v1"}

class ExternalGatewayTests(unittest.TestCase):
    def test_disabled_by_default_and_no_provider_inferred(self):
        gateway=ExternalIntegrationGateway()
        with self.assertRaisesRegex(ExternalIntegrationError,"disabled"):
            gateway.invoke("IF-01",request())

    def test_missing_provider_contract_fails_closed(self):
        gateway=ExternalIntegrationGateway(enabled=True,audit_sink=lambda e:None)
        with self.assertRaisesRegex(ExternalIntegrationError,"no provider contract"):
            gateway.invoke("IF-01",request())

    def test_rejects_non_https_or_unallowlisted_host(self):
        with self.assertRaises(ExternalIntegrationError):
            ProviderBinding("IF-01","bad","http://api.example.test",("api.example.test",),{"VALIDATE":"x"}).validate()
        with self.assertRaises(ExternalIntegrationError):
            ProviderBinding("IF-01","bad","https://evil.test",("api.example.test",),{"VALIDATE":"x"}).validate()

    def test_success_is_audited_and_idempotent_in_process(self):
        transport=FakeTransport(); events=[]
        gateway=ExternalIntegrationGateway((binding(),),transport=transport,
            audit_sink=events.append,credential_resolver=lambda p:{"Authorization":"Bearer test-secret"},enabled=True)
        authority={"external_action_authorisation":True}
        first=gateway.invoke("IF-01",request(),authority=authority)
        second=gateway.invoke("IF-01",request(),authority=authority)
        self.assertEqual(first,second); self.assertEqual(len(transport.calls),1)
        self.assertEqual(first["status"],"PROVIDER_CONFIRMED")
        self.assertEqual([e["phase"] for e in events],["REQUESTED","COMPLETED"])
        self.assertNotIn("test-secret",json.dumps(events))

    def test_write_requires_explicit_authority(self):
        gateway=ExternalIntegrationGateway((binding(),),transport=FakeTransport(),
            audit_sink=lambda e:None,enabled=True)
        with self.assertRaisesRegex(ExternalIntegrationError,"lacks explicit authority"):
            gateway.invoke("IF-01",request("EXTERNAL_WRITE"))

    def test_write_with_authority_uses_idempotency_header(self):
        transport=FakeTransport(); gateway=ExternalIntegrationGateway((binding(),),transport=transport,
            audit_sink=lambda e:None,enabled=True)
        result=gateway.invoke("IF-01",request("EXTERNAL_WRITE"),
            authority={"external_action_authorisation":True})
        self.assertEqual(result["status"],"PROVIDER_CONFIRMED")
        self.assertIn("Idempotency-Key",transport.calls[0][1])

    def test_requires_audit_sink_before_call(self):
        gateway=ExternalIntegrationGateway((binding(),),transport=FakeTransport(),enabled=True)
        with self.assertRaisesRegex(ExternalIntegrationError,"audit sink"):
            gateway.invoke("IF-01",request())

    def test_non_success_provider_response_is_not_reported_as_success(self):
        gateway=ExternalIntegrationGateway((binding(),),transport=FakeTransport(503),
            audit_sink=lambda e:None,enabled=True)
        with self.assertRaisesRegex(ExternalIntegrationError,"HTTP 503"):
            gateway.invoke("IF-01",request(),
                authority={"external_action_authorisation":True})

class AssuranceTests(unittest.TestCase):
    def test_empty_evidence_is_not_ready(self):
        result=assess_production_readiness({"implementation_owner_id":"builder"})
        self.assertEqual(result.status,"NOT_PRODUCTION_READY")
        self.assertFalse(result.independence_verified)
        self.assertEqual(len(result.missing_domains),8)

    def test_implementer_cannot_self_certify_independence(self):
        evidence={"implementation_owner_id":"builder"}
        for domain in ("provider_contracts","identity_and_secrets","network_and_data_controls",
                       "idempotency_and_recovery","audit_and_monitoring","security_testing","production_e2e"):
            evidence[domain]={"status":"VERIFIED","evidence_ref":"evidence:"+domain}
        evidence["independent_review"]={"status":"VERIFIED","evidence_ref":"review:1","reviewer_id":"builder"}
        result=assess_production_readiness(evidence)
        self.assertFalse(result.independence_verified)
        self.assertIn("independent_review",result.missing_domains)
        self.assertEqual(result.status,"NOT_PRODUCTION_READY")

    def test_distinct_reviewer_and_complete_evidence_can_pass_gate(self):
        evidence={"implementation_owner_id":"builder"}
        for domain in ("provider_contracts","identity_and_secrets","network_and_data_controls",
                       "idempotency_and_recovery","audit_and_monitoring","security_testing","production_e2e"):
            evidence[domain]={"status":"VERIFIED","evidence_ref":"evidence:"+domain}
        evidence["independent_review"]={"status":"VERIFIED","evidence_ref":"review:1","reviewer_id":"reviewer"}
        result=assess_production_readiness(evidence)
        self.assertTrue(result.independence_verified)
        self.assertEqual(result.status,"PRODUCTION_READY_FOR_RELEASE_REVIEW")

if __name__=="__main__": unittest.main()
