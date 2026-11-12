import hashlib
import tempfile
import unittest
from pathlib import Path

from rhemascript.evidence.evidence_pack import validate_evidence_pack
from rhemascript.evidence.evidence_pack_integrity import EvidencePackIntegrityError, verify_pack_artifacts

PROJECT = {"record_id":"RS-EVIDENCE-001","record_type":"SYNTHETIC_PROJECT","schema_version":"1.0","project_id":"RS-PROJECT-001","status":"DRAFT","classification":"OPERATIONAL","version":"1.0"}

def make_pack(digest, local_path="proof.txt"):
    return {"manifest_id":"M-1","schema_version":"1.0","project_record":dict(PROJECT),
      "artifacts":[{"artifact_id":"A-1","project_id":PROJECT["project_id"],"project_version":"1.0",
        "artifact_type":"BIBLICAL_SOURCE","version":"v1","status":"VERIFIED",
        "local_path":local_path,"sha256":digest,"evidence_refs":[]}],
      "evidence_records":[],"source_to_final_links":[]}

class EvidencePackIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.content=b"verified file bytes"
        (self.root/"proof.txt").write_bytes(self.content)
        self.digest=hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def test_verified_pack_artifact_requires_matching_bytes(self):
        pack=validate_evidence_pack(make_pack(self.digest))
        versions=verify_pack_artifacts(pack,self.root)
        self.assertEqual(versions[0].sha256,self.digest)

    def test_forged_verified_status_without_file_is_rejected(self):
        pack=validate_evidence_pack(make_pack(self.digest, "missing.txt"))
        with self.assertRaises(EvidencePackIntegrityError):
            verify_pack_artifacts(pack,self.root)

    def test_modified_file_is_rejected_against_manifest_digest(self):
        pack=validate_evidence_pack(make_pack(self.digest))
        (self.root/"proof.txt").write_bytes(b"tampered")
        with self.assertRaisesRegex(EvidencePackIntegrityError,"does not match"):
            verify_pack_artifacts(pack,self.root)

    def test_verified_status_without_digest_is_rejected(self):
        data=make_pack(self.digest); del data["artifacts"][0]["sha256"]
        pack=validate_evidence_pack(data)
        with self.assertRaises(EvidencePackIntegrityError):
            verify_pack_artifacts(pack,self.root)

    def test_unverified_draft_does_not_claim_byte_verification(self):
        data=make_pack(self.digest); data["artifacts"][0]["status"]="DRAFT"
        del data["artifacts"][0]["local_path"]; del data["artifacts"][0]["sha256"]
        self.assertEqual(verify_pack_artifacts(validate_evidence_pack(data),self.root),())

if __name__=="__main__": unittest.main()
