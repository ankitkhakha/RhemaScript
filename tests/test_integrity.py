import unittest
from raei.integrity import STAGES, GATES, IntegrityError, validate_project_chain

def complete_project():
    stages = {name: {"status":"present","artifact_ref":name+"-v1","source_ref":"source:"+name,"revision":1}
              for name in STAGES}
    for index, name in enumerate(STAGES[1:], start=1):
        stages[name]["upstream_refs"] = [stages[STAGES[index-1]]["artifact_ref"]]
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

    def test_missing_predecessor_dependency_is_rejected(self):
        project=complete_project()
        project["stages"]["approved_script"]["upstream_refs"]=[]
        result=validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any("predecessor dependency: approved_script" in e for e in result["errors"]))

    def test_invalid_revision_is_rejected(self):
        project=complete_project()
        project["stages"]["storyboard"]["revision"]=0
        self.assertFalse(validate_project_chain(project)["valid"])

    def test_duplicate_stage_artifact_reference_is_rejected(self):
        project=complete_project()
        project["stages"]["edited_film"]["artifact_ref"]=project["stages"]["asset"]["artifact_ref"]
        self.assertFalse(validate_project_chain(project)["valid"])

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


    def test_approval_must_explicitly_reference_current_artifact(self):
        project=complete_project()
        project["approvals"]["biblical_accuracy"]["artifact_ref"]=None
        result=validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any("current stage artefact: biblical_accuracy" in e for e in result["errors"]))

    def test_revision_history_must_be_contiguous(self):
        project=complete_project()
        project["revision_history"]=[
            {"stage":"biblical_source","revision":1,"previous_artifact_ref":None,
             "artifact_ref":"biblical_source-v1","source_ref":"source:biblical_source","change_reason":"Initial"},
            {"stage":"biblical_source","revision":3,"previous_artifact_ref":"biblical_source-v1",
             "artifact_ref":"biblical_source-v3","source_ref":"source:biblical_source","change_reason":"Correction"},
        ]
        project["stages"]["biblical_source"]["revision"]=3
        project["stages"]["biblical_source"]["artifact_ref"]="biblical_source-v3"
        result=validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any("non-contiguous revision history" in e for e in result["errors"]))

    def test_revision_history_must_match_current_snapshot(self):
        project=complete_project()
        project["revision_history"]=[
            {"stage":"biblical_source","revision":1,"previous_artifact_ref":None,
             "artifact_ref":"stale-source","source_ref":"bible:ref","change_reason":"Initial"}
        ]
        result=validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any("does not match current stage snapshot" in e for e in result["errors"]))

    def test_missing_project_identity_is_rejected(self):
        with self.assertRaises(IntegrityError):
            validate_project_chain({"stages":{},"approvals":{}})


    def test_project_identity_must_be_nonempty_string(self):
        for value in (" ", 17, [], {}):
            project = complete_project()
            project["project_id"] = value
            with self.subTest(value=value), self.assertRaises(IntegrityError):
                validate_project_chain(project)

    def test_stage_source_reference_must_be_nonempty_string(self):
        for value in (" ", 17, [], {}):
            project = complete_project()
            project["stages"]["approved_script"]["source_ref"] = value
            result = validate_project_chain(project)
            self.assertFalse(result["valid"])
            self.assertTrue(any("source reference: approved_script" in e for e in result["errors"]))

    def test_approval_evidence_must_be_nonempty_string(self):
        for value in (" ", 17, [], {}):
            project = complete_project()
            project["approvals"]["final_film"]["approval_ref"] = value
            result = validate_project_chain(project)
            self.assertFalse(result["valid"])
            self.assertTrue(any("approval evidence: final_film" in e for e in result["errors"]))

    def test_malformed_artifact_reference_does_not_crash_duplicate_check(self):
        project = complete_project()
        project["stages"]["asset"]["artifact_ref"] = []
        result = validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any("artifact reference: asset" in e for e in result["errors"]))

    def test_generation_flags_must_be_boolean(self):
        project = complete_project()
        project["generation"] = {"authorized": "false", "performed": 0}
        result = validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any("authorized flag must be boolean" in e for e in result["errors"]))
        self.assertTrue(any("performed flag must be boolean" in e for e in result["errors"]))

    def test_malformed_asset_stage_does_not_crash_generation_check(self):
        project = complete_project()
        project["stages"]["asset"] = []
        project["generation"] = {"authorized": True, "performed": True,
                                 "authorization_ref": "approval:generation",
                                 "asset_ref": "asset-v1"}
        result = validate_project_chain(project)
        self.assertFalse(result["valid"])
        self.assertTrue(any("generation output does not match" in e for e in result["errors"]))

if __name__=="__main__":
    unittest.main(verbosity=2)
