import unittest
from rhemascript.evidence import EvidencePackError, run_evidence_pack, validate_evidence_pack

PROJECT = {"record_id":"RS-EVIDENCE-001","record_type":"SYNTHETIC_PROJECT","schema_version":"1.0","project_id":"RS-PROJECT-001","status":"DRAFT","classification":"OPERATIONAL","version":"1.0"}

def pack():
    return {"manifest_id":"RS-MANIFEST-001","schema_version":"1.0","project_record":dict(PROJECT),
      "artifacts":[{"artifact_id":"SRC-1","project_id":PROJECT["project_id"],"project_version":"1.0","artifact_type":"BIBLICAL_SOURCE","version":"1","status":"VERIFIED","evidence_refs":["bible:ref"]}],
      "evidence_records":[{"evidence_id":"EV-1","capability_id":"CAP-01","payload":{"sources":[{"source_ref":"bible:ref"}]},"evidence_refs":["bible:ref"],"artifact_refs":["SRC-1"]}],
      "source_to_final_links":[]}

class EvidencePackTests(unittest.TestCase):
    def test_valid_pack_compiles_capability_evidence(self):
        result=validate_evidence_pack(pack())
        self.assertEqual(result.capability_evidence["CAP-01"]["sources"],[{"source_ref":"bible:ref"}])
        self.assertIn("artifact:SRC-1",result.capability_evidence["CAP-01"]["evidence_refs"])
    def test_duplicate_artifact_id_rejected(self):
        p=pack(); p["artifacts"].append(dict(p["artifacts"][0]))
        with self.assertRaisesRegex(EvidencePackError,"duplicate artifact_id"): validate_evidence_pack(p)
    def test_project_version_mismatch_rejected(self):
        p=pack(); p["artifacts"][0]["project_version"]="2.0"
        with self.assertRaisesRegex(EvidencePackError,"not bound"): validate_evidence_pack(p)
    def test_unknown_artifact_reference_rejected(self):
        p=pack(); p["evidence_records"][0]["artifact_refs"]=["NOPE"]
        with self.assertRaisesRegex(EvidencePackError,"unknown artifact"): validate_evidence_pack(p)
    def test_provenance_cycle_rejected(self):
        p=pack(); p["artifacts"].append({"artifact_id":"A","project_id":PROJECT["project_id"],"project_version":"1.0","artifact_type":"ASSET","version":"1","status":"DRAFT"})
        p["source_to_final_links"]=[{"from_artifact_id":"SRC-1","to_artifact_id":"A","relationship":"derived_from"},{"from_artifact_id":"A","to_artifact_id":"SRC-1","relationship":"derived_from"}]
        with self.assertRaisesRegex(EvidencePackError,"cycle"): validate_evidence_pack(p)
    def test_final_film_requires_complete_connected_chain(self):
        p=pack(); previous="SRC-1"
        for i,kind in enumerate(("APPROVED_SCRIPT","APPROVED_NARRATION","STORYBOARD","AUDIO_VISUAL_PLAN","PROMPT","ASSET","EDITED_FILM"),1):
            ident=f"A-{i}"; p["artifacts"].append({"artifact_id":ident,"project_id":PROJECT["project_id"],"project_version":"1.0","artifact_type":kind,"version":"1","status":"APPROVED" if kind.startswith("APPROVED_") else "VERIFIED"})
            p["source_to_final_links"].append({"from_artifact_id":previous,"to_artifact_id":ident,"relationship":"derived_from"}); previous=ident
        validate_evidence_pack(p); p["source_to_final_links"].pop()
        with self.assertRaisesRegex(EvidencePackError,"disconnected"): validate_evidence_pack(p)
    def test_each_edited_film_requires_its_own_complete_source_to_final_chain(self):
        p = pack()
        previous = "SRC-1"
        for i, kind in enumerate(("APPROVED_SCRIPT", "APPROVED_NARRATION", "STORYBOARD",
                                  "AUDIO_VISUAL_PLAN", "PROMPT", "ASSET", "EDITED_FILM"), 1):
            ident = f"CHAIN-{i}"
            p["artifacts"].append({
                "artifact_id": ident, "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"], "artifact_type": kind,
                "version": "1", "status": "APPROVED" if kind.startswith("APPROVED_") else "VERIFIED",
            })
            p["source_to_final_links"].append({
                "from_artifact_id": previous, "to_artifact_id": ident, "relationship": "derived_from",
            })
            previous = ident
        p["artifacts"].append({
            "artifact_id": "ORPHAN-FILM", "project_id": PROJECT["project_id"],
            "project_version": PROJECT["version"], "artifact_type": "EDITED_FILM",
            "version": "1", "status": "VERIFIED",
        })
        with self.assertRaisesRegex(EvidencePackError, "ORPHAN-FILM.*complete ordered source-to-final chain"):
            validate_evidence_pack(p)

    def test_pairwise_chain_segments_cannot_be_spliced_from_disconnected_branches(self):
        p = pack()
        nodes = [
            ("SCRIPT-FROM-SOURCE", "APPROVED_SCRIPT"),
            ("SCRIPT-DETACHED", "APPROVED_SCRIPT"),
            ("NARRATION-FROM-DETACHED", "APPROVED_NARRATION"),
            ("NARRATION-DETACHED", "APPROVED_NARRATION"),
            ("STORYBOARD", "STORYBOARD"),
            ("PLAN", "AUDIO_VISUAL_PLAN"),
            ("PROMPT", "PROMPT"),
            ("ASSET", "ASSET"),
            ("FILM", "EDITED_FILM"),
        ]
        for ident, kind in nodes:
            p["artifacts"].append({
                "artifact_id": ident, "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"], "artifact_type": kind,
                "version": "1", "status": "APPROVED" if kind.startswith("APPROVED_") else "VERIFIED",
            })
        p["source_to_final_links"].extend([
            {"from_artifact_id": "SRC-1", "to_artifact_id": "SCRIPT-FROM-SOURCE", "relationship": "derived_from"},
            {"from_artifact_id": "SCRIPT-DETACHED", "to_artifact_id": "NARRATION-FROM-DETACHED", "relationship": "derived_from"},
            {"from_artifact_id": "NARRATION-DETACHED", "to_artifact_id": "STORYBOARD", "relationship": "derived_from"},
            {"from_artifact_id": "STORYBOARD", "to_artifact_id": "PLAN", "relationship": "derived_from"},
            {"from_artifact_id": "PLAN", "to_artifact_id": "PROMPT", "relationship": "derived_from"},
            {"from_artifact_id": "PROMPT", "to_artifact_id": "ASSET", "relationship": "derived_from"},
            {"from_artifact_id": "ASSET", "to_artifact_id": "FILM", "relationship": "derived_from"},
        ])
        with self.assertRaisesRegex(EvidencePackError, "FILM.*complete ordered source-to-final chain"):
            validate_evidence_pack(p)

    def test_script_approval_not_inferred(self):
        p=pack(); p["artifacts"].append({"artifact_id":"S","project_id":PROJECT["project_id"],"project_version":"1.0","artifact_type":"APPROVED_SCRIPT","version":"1","status":"DRAFT"})
        with self.assertRaisesRegex(EvidencePackError,"approval status"): validate_evidence_pack(p)
    def test_run_does_not_perform_actions(self):
        _, result=run_evidence_pack(pack(),actor_role="TEST_HARNESS")
        self.assertEqual(result.run_id,"RS-MANIFEST-001:1.0")
        self.assertFalse(result.generation_action_performed); self.assertFalse(result.external_action_performed); self.assertFalse(result.publishing_performed)



    def test_legacy_run_is_explicitly_structural_only(self):
        validated, _ = run_evidence_pack(pack(), actor_role="TEST_HARNESS")
        self.assertEqual(validated.evidence_integrity_mode, "STRUCTURAL_ONLY")
        self.assertEqual(validated.byte_verified_artifacts, ())

    def test_strict_run_rejects_verified_status_without_local_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "without local_path"):
                run_evidence_pack(pack(), actor_role="TEST_HARNESS", evidence_root=root)

    def test_strict_run_binds_verified_artifact_to_actual_bytes(self):
        import hashlib
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            content = b"actual source evidence"
            (Path(root) / "source.txt").write_bytes(content)
            p = pack()
            p["artifacts"][0]["local_path"] = "source.txt"
            p["artifacts"][0]["sha256"] = hashlib.sha256(content).hexdigest()
            validated, result = run_evidence_pack(
                p, actor_role="TEST_HARNESS", evidence_root=root
            )
            self.assertEqual(validated.evidence_integrity_mode, "BYTE_VERIFIED")
            self.assertEqual(len(validated.byte_verified_artifacts), 1)
            self.assertEqual(validated.byte_verified_artifacts[0].sha256,
                             hashlib.sha256(content).hexdigest())
            self.assertFalse(result.generation_action_performed)

    def test_strict_run_rejects_modified_artifact_bytes(self):
        import hashlib
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            content = b"expected source evidence"
            (Path(root) / "source.txt").write_bytes(b"modified bytes")
            p = pack()
            p["artifacts"][0]["local_path"] = "source.txt"
            p["artifacts"][0]["sha256"] = hashlib.sha256(content).hexdigest()
            with self.assertRaisesRegex(ValueError, "does not match declared SHA-256"):
                run_evidence_pack(p, actor_role="TEST_HARNESS", evidence_root=root)


    def test_local_source_resolver_binds_exact_source_bytes_and_receipt(self):
        import hashlib
        import tempfile
        from pathlib import Path
        from rhemascript.evidence.local_source_resolver import LocalSourceEntry, LocalSourceResolver
        with tempfile.TemporaryDirectory() as root:
            content = b"catalogued scripture source"
            (Path(root) / "source.txt").write_bytes(content)
            reference = "local-source:corpus:GEN-1-1"
            p = pack()
            p["artifacts"][0].update({
                "local_source_reference": reference,
                "sha256": hashlib.sha256(content).hexdigest(),
            })
            resolver = LocalSourceResolver(root, {
                reference: LocalSourceEntry(
                    reference=reference, source_id="SRC-1", relative_path="source.txt",
                    version="1", expected_sha256=hashlib.sha256(content).hexdigest(),
                    media_type="text/plain", catalog_revision="catalog-v1",
                    project_id=PROJECT["project_id"], project_version=PROJECT["version"],
                )
            })
            validated, result = run_evidence_pack(
                p, actor_role="TEST_HARNESS", local_source_resolver=resolver
            )
            self.assertEqual(validated.evidence_integrity_mode, "BYTE_VERIFIED")
            self.assertEqual(len(validated.byte_verified_artifacts), 1)
            self.assertEqual(len(validated.source_resolution_receipts), 1)
            receipt = validated.source_resolution_receipts[0]
            self.assertEqual(receipt.outcome, "CONTENT_VERIFIED")
            self.assertEqual(receipt.source_authentication, "NOT_CHECKED")
            self.assertEqual(receipt.claim_relevance, "NOT_CHECKED")
            self.assertFalse(result.generation_action_performed)
            self.assertFalse(result.external_action_performed)
            self.assertFalse(result.publishing_performed)

    def test_local_source_resolver_rejects_artifact_digest_disagreement(self):
        import hashlib
        import tempfile
        from pathlib import Path
        from rhemascript.evidence.local_source_resolver import LocalSourceEntry, LocalSourceResolver
        with tempfile.TemporaryDirectory() as root:
            content = b"catalogued source"
            (Path(root) / "source.txt").write_bytes(content)
            reference = "local-source:corpus:GEN-1-1"
            p = pack()
            p["artifacts"][0].update({"local_source_reference": reference, "sha256": "0" * 64})
            resolver = LocalSourceResolver(root, {
                reference: LocalSourceEntry(
                    reference=reference, source_id="SRC-1", relative_path="source.txt",
                    version="1", expected_sha256=hashlib.sha256(content).hexdigest(),
                    media_type="text/plain", catalog_revision="catalog-v1",
                    project_id=PROJECT["project_id"], project_version=PROJECT["version"],
                )
            })
            with self.assertRaisesRegex(EvidencePackError, "SHA-256 does not match"):
                run_evidence_pack(p, actor_role="TEST_HARNESS", local_source_resolver=resolver)


    def test_local_source_reference_from_another_project_is_rejected(self):
        import hashlib
        import tempfile
        from pathlib import Path
        from rhemascript.evidence.local_source_resolver import LocalSourceEntry, LocalSourceResolver
        with tempfile.TemporaryDirectory() as root:
            content = b"foreign project source"
            (Path(root) / "source.txt").write_bytes(content)
            reference = "local-source:foreign-project"
            p = pack()
            p["artifacts"][0].update({
                "local_source_reference": reference,
                "sha256": hashlib.sha256(content).hexdigest(),
            })
            resolver = LocalSourceResolver(root, {
                reference: LocalSourceEntry(
                    reference=reference, source_id="SRC-1", relative_path="source.txt",
                    version="1", expected_sha256=hashlib.sha256(content).hexdigest(),
                    media_type="text/plain", catalog_revision="catalog-v1",
                    project_id="RS-OTHER-PROJECT", project_version="1.0",
                )
            })
            with self.assertRaisesRegex(EvidencePackError, "could not be verified"):
                run_evidence_pack(p, actor_role="TEST_HARNESS", local_source_resolver=resolver)

    def test_unknown_capability_id_rejected(self):
        p=pack(); p["evidence_records"][0]["capability_id"]="CAP-99"
        with self.assertRaisesRegex(EvidencePackError,"unknown capability"): validate_evidence_pack(p)
    def test_non_string_artifact_type_rejected_without_type_error(self):
        p=pack(); p["artifacts"][0]["artifact_type"]={"unexpected":"object"}
        with self.assertRaisesRegex(EvidencePackError,"unsupported artifact_type"): validate_evidence_pack(p)
    def test_non_string_artifact_reference_rejected_without_type_error(self):
        p=pack(); p["evidence_records"][0]["artifact_refs"]=[["not","hashable"]]
        with self.assertRaisesRegex(EvidencePackError,"artifact_refs must contain"): validate_evidence_pack(p)
    def test_payload_cannot_override_audit_evidence_references(self):
        p=pack(); p["evidence_records"][0]["payload"]["evidence_refs"]=["forged"]
        with self.assertRaisesRegex(EvidencePackError,"reserved evidence_refs"): validate_evidence_pack(p)

if __name__=="__main__": unittest.main()
