import unittest
from raei.integrity import STAGES, GATES, IntegrityError, validate_project_chain

def complete_project():
    stages = {name: {"status":"present","artifact_ref":name+"-v1","source_ref":"source:"+name}
              for name in STAGES}
    gate_stage = {
        "creative_direction":"biblical_source","biblical_accuracy":"approved_script",
        "visual_development":"storyboard","production_plan_prompt":"clip_prompt",
        "generation_authorisation":"asset","final_film":"edited_film"
    }
    approvals = {gate: {"status":"approved","approval_ref":"approval:"+gate,
                        "artifact_ref":stages[gate_stage[gate]]["artifact_ref"]}
                 for gate in GATES}
    return {"project_id":"RS-TEST-001","stages":stages,"approvals":approvals,
            "generation":{"authorized":False,"performed":False},"published":False}

class IntegrityChainTests(unittest.TestCase):
    def test_complete_trace_is_valid_without_granting_authority(self):
        result=validate_project_chain(complete_project())
        self.assertTrue(result["valid"],result["errors"])
        self.assertEqual("not_granted_by_validator",result["generation_authority"])
        self.assertEqual("not_granted_by_validator",result["publishing_authority"])

    def test_missing_stage_artifact_is_rejected(self):
        project=complete_project()
        project["stages"]["approved_narration"]["artifact_ref"]=""
        result=validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any("artifact reference: approved_narration" in e for e in result["errors"]))

    def test_unapproved_gate_is_rejected(self):
        project=complete_project()
        project["approvals"]["biblical_accuracy"]["status"]="pending"
        self.assertFalse(validate_project_chain(project)["valid"])

    def test_gate_must_reference_current_stage_artifact(self):
        project=complete_project()
        project["approvals"]["final_film"]["artifact_ref"]="old-edit"
        self.assertFalse(validate_project_chain(project)["valid"])

    def test_unauthorized_generation_is_critical_failure(self):
        project=complete_project()
        project["generation"]={"authorized":False,"performed":True,"asset_ref":"asset-v1"}
        result=validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any(e.startswith("critical:") for e in result["errors"]))

    def test_generation_authorization_requires_reference(self):
        project=complete_project()
        project["generation"]={"authorized":True,"performed":False}
        self.assertFalse(validate_project_chain(project)["valid"])

    def test_published_project_is_outside_validator_authority(self):
        project=complete_project()
        project["published"]=True
        self.assertFalse(validate_project_chain(project)["valid"])

    def test_missing_project_identity_is_rejected(self):
        with self.assertRaises(IntegrityError):
            validate_project_chain({"stages":{},"approvals":{}})

if __name__=="__main__":
    unittest.main(verbosity=2)
