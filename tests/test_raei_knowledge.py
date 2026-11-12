import hashlib
import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from rhemascript.evidence.artifact_verification import verify_artifact, EvidenceVersion
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry, ReadinessReplayError
from raei.knowledge import (
    RAEIKnowledgeError,
    SCHEMA,
    canonical_knowledge_bytes,
    list_knowledge,
    record_knowledge,
    search_knowledge,
)


class RAEIKnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "evidence"
        self.root.mkdir()
        self.registry = ReadinessRunRegistry(Path(self.tmp.name) / "knowledge.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def make_item(self, *, knowledge_id="RS-KNOW-001", version="1.0", source_type="OFFICIAL_DOC"):
        authority = {
            "BIBLE": "SCRIPTURE",
            "OFFICIAL_DOC": "OFFICIAL_PRIMARY",
            "INTERNAL_SPEC": "INTERNAL_APPROVED",
            "CODE": "UNVERIFIED",
            "SECONDARY": "SECONDARY",
            "LESSON_FROM_FAILURE": "UNVERIFIED",
        }[source_type]
        payload = {
            "schema": SCHEMA,
            "knowledge_id": knowledge_id,
            "version": version,
            "title": "Official Python packaging guidance",
            "domain": "engineering",
            "source_type": source_type,
            "authority_level": authority,
            "source_name": "Python Packaging User Guide",
            "source_version": "2026-11",
            "source_reference": "local://sources/python-packaging-guide.pdf",
            "summary": "Packaging guidance for reliable local application builds.",
            "claims": ["Editable installs must include declared runtime dependencies."],
            "limitations": ["Applies to the documented packaging version."],
            "tags": ["python", "packaging", "build"],
            "evidence_id": f"EV-{knowledge_id}-{version}",
            "evidence_version": version,
            "status": "PENDING_REVIEW",
            "source_authentication_status": "NOT_CHECKED",
            "claim_relevance_status": "NOT_ASSESSED",
            "created_at_utc": "2026-11-12T12:00:00+00:00",
            "supersedes": [],
        }
        if source_type == "BIBLE":
            payload.update({
                "language": "hi",
                "translation_version": "HINOVBSI",
                "direct_scripture_quote": True,
            })
        if source_type == "LESSON_FROM_FAILURE":
            payload.update({
                "failure_attempt_id": "ATT-FAILED-001",
                "root_cause": "A replayed assessment was not rejected.",
                "remediation": "Bind assessment ID and evidence digest and add a replay test.",
                "regression_test_refs": ["tests/test_raei_training.py::test_replay_with_changed_assessment_is_rejected"],
                "affected_unit_ids": ["SECURE-CODE", "AI-EVALUATION"],
            })
        relative = f"{knowledge_id}-{version}.json"
        (self.root / relative).write_bytes(canonical_knowledge_bytes(payload))
        evidence = verify_artifact(
            self.root, relative, evidence_id=payload["evidence_id"], version=version
        )
        return payload, evidence

    def reverify(self, payload, evidence):
        (self.root / evidence.relative_path).write_bytes(canonical_knowledge_bytes(payload))
        return verify_artifact(
            self.root, evidence.relative_path,
            evidence_id=payload["evidence_id"], version=payload["evidence_version"],
        )

    def test_records_exact_verified_knowledge_as_pending_review(self):
        payload, evidence = self.make_item()
        report = record_knowledge(self.registry, payload, evidence)
        self.assertEqual(report["record_type"], "RAEI_KNOWLEDGE_ITEM_V1")
        items = list_knowledge(self.registry)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["status"], "PENDING_REVIEW")
        self.assertEqual(items[0]["source_authentication_status"], "NOT_CHECKED")
        self.assertEqual(items[0]["claim_relevance_status"], "NOT_ASSESSED")

    def test_pending_knowledge_is_hidden_from_default_search(self):
        payload, evidence = self.make_item()
        record_knowledge(self.registry, payload, evidence)
        self.assertEqual(search_knowledge(self.registry, "Python packaging"), [])
        self.assertEqual(len(search_knowledge(self.registry, "Python packaging", include_pending=True)), 1)

    def test_payload_must_match_exact_verified_bytes(self):
        payload, evidence = self.make_item()
        changed = {**payload, "summary": "Changed after verification"}
        with self.assertRaisesRegex(RAEIKnowledgeError, "does not match"):
            record_knowledge(self.registry, changed, evidence)

    def test_status_cannot_be_self_approved(self):
        payload, evidence = self.make_item()
        changed = {**payload, "status": "APPROVED"}
        changed_evidence = self.reverify(changed, evidence)
        with self.assertRaisesRegex(RAEIKnowledgeError, "PENDING_REVIEW"):
            record_knowledge(self.registry, changed, changed_evidence)

    def test_hash_verification_cannot_claim_source_authenticity_or_relevance(self):
        payload, evidence = self.make_item()
        changed = {**payload, "source_authentication_status": "VERIFIED"}
        changed_evidence = self.reverify(changed, evidence)
        with self.assertRaisesRegex(RAEIKnowledgeError, "source authentication"):
            record_knowledge(self.registry, changed, changed_evidence)

    def test_hindi_direct_scripture_quote_requires_hinovbsi(self):
        payload, evidence = self.make_item(source_type="BIBLE")
        changed = {**payload, "translation_version": "OTHER-HINDI-TRANSLATION"}
        changed_evidence = self.reverify(changed, evidence)
        with self.assertRaisesRegex(RAEIKnowledgeError, "HINOVBSI"):
            record_knowledge(self.registry, changed, changed_evidence)

    def test_failure_lesson_requires_root_cause_remediation_and_regression_tests(self):
        payload, evidence = self.make_item(source_type="LESSON_FROM_FAILURE")
        changed = {**payload}
        del changed["root_cause"]
        changed_evidence = self.reverify(changed, evidence)
        with self.assertRaisesRegex(RAEIKnowledgeError, "root_cause"):
            record_knowledge(self.registry, changed, changed_evidence)

    def test_supersedes_must_reference_existing_knowledge_version(self):
        payload, evidence = self.make_item(version="2.0")
        changed = {**payload, "supersedes": ["RS-KNOW-OLD@1.0"]}
        changed_evidence = self.reverify(changed, evidence)
        with self.assertRaisesRegex(RAEIKnowledgeError, "does not exist"):
            record_knowledge(self.registry, changed, changed_evidence)

    def test_valid_new_version_supersedes_existing_item_without_overwriting_it(self):
        first, evidence1 = self.make_item()
        record_knowledge(self.registry, first, evidence1)
        second, evidence2 = self.make_item(version="2.0")
        second["supersedes"] = ["RS-KNOW-001@1.0"]
        evidence2 = self.reverify(second, evidence2)
        record_knowledge(self.registry, second, evidence2)
        self.assertEqual([x["version"] for x in list_knowledge(self.registry)], ["1.0", "2.0"])

    def test_rewritten_approved_status_is_rejected_on_read(self):
        payload, evidence = self.make_item()
        record_knowledge(self.registry, payload, evidence)
        run_id = "KNOWLEDGE:RS-KNOW-001:1.0"
        stored = self.registry.get(run_id)
        stored["report"]["knowledge_payload"]["status"] = "APPROVED"
        encoded = json.dumps(stored, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.registry.database) as db:
            db.execute(
                "UPDATE readiness_runs SET payload_sha256=?, payload_json=? WHERE run_id=?",
                (digest, encoded, run_id),
            )
        self.assertTrue(self.registry.verify())
        with self.assertRaisesRegex(RAEIKnowledgeError, "PENDING_REVIEW"):
            list_knowledge(self.registry)

    def test_forged_evidence_dataclass_is_rejected(self):
        payload, evidence = self.make_item()
        forged = EvidenceVersion(
            evidence.evidence_id, evidence.relative_path, evidence.version,
            evidence.sha256, evidence.size_bytes,
        )
        with self.assertRaisesRegex(RAEIKnowledgeError, "exact EvidenceVersion"):
            record_knowledge(self.registry, payload, forged)


if __name__ == "__main__":
    unittest.main()
