from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from rhemascript.evidence.local_source_resolver import (
    LocalSourceEntry,
    LocalSourceResolutionError,
    LocalSourceResolver,
)


def entry(reference: str, path: str, content: bytes, project_id="PROJECT-1", project_version="1.0") -> LocalSourceEntry:
    return LocalSourceEntry(
        reference=reference,
        source_id="SRC-001",
        relative_path=path,
        version="v1",
        expected_sha256=hashlib.sha256(content).hexdigest(),
        media_type="text/plain",
        catalog_revision="catalog-v1",
    )


class LocalSourceResolverTests(unittest.TestCase):
    def test_resolves_exact_reference_and_limits_claim_to_content_identity(self):
        with tempfile.TemporaryDirectory() as root:
            content = b"Approved local source bytes"
            (Path(root) / "source.txt").write_bytes(content)
            reference = "local-source:scripture-corpus:GEN-1-1"
            resolver = LocalSourceResolver(root, {reference: entry(reference, "source.txt", content)})
            evidence, receipt = resolver.resolve(reference)
            self.assertEqual(evidence.sha256, hashlib.sha256(content).hexdigest())
            self.assertEqual(receipt.outcome, "CONTENT_VERIFIED")
            self.assertEqual(receipt.source_authentication, "NOT_CHECKED")
            self.assertEqual(receipt.claim_relevance, "NOT_CHECKED")
            self.assertEqual(receipt.original_reference, reference)

    def test_unknown_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            known = "local-source:known"
            resolver = LocalSourceResolver(root, {known: entry(known, "source.txt", b"x")})
            with self.assertRaises(LocalSourceResolutionError):
                resolver.resolve("local-source:unknown")

    def test_changed_bytes_fail_catalog_digest_check(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "source.txt").write_bytes(b"substituted")
            reference = "local-source:approved"
            resolver = LocalSourceResolver(root, {reference: entry(reference, "source.txt", b"original")})
            with self.assertRaises(LocalSourceResolutionError):
                resolver.resolve(reference)

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            reference = "local-source:traversal"
            resolver = LocalSourceResolver(root, {reference: entry(reference, "../outside.txt", b"x")})
            with self.assertRaises(LocalSourceResolutionError):
                resolver.resolve(reference)

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside_root:
            outside = Path(outside_root) / "outside-source.txt"
            outside.write_bytes(b"source")
            (Path(root) / "source-link.txt").symlink_to(outside)
            reference = "local-source:symlink"
            resolver = LocalSourceResolver(root, {reference: entry(reference, "source-link.txt", b"source")})
            with self.assertRaises(LocalSourceResolutionError):
                resolver.resolve(reference)


    def test_receipt_is_bound_to_exact_catalog_snapshot_and_stale_after_replacement(self):
        with tempfile.TemporaryDirectory() as root:
            content = b"catalog revision one"
            (Path(root) / "source.txt").write_bytes(content)
            reference = "local-source:source"
            original = entry(reference, "source.txt", content)
            resolver_v1 = LocalSourceResolver(root, {reference: original})
            _, receipt = resolver_v1.resolve(
                reference, project_id="PROJECT-1", project_version="1.0"
            )
            self.assertTrue(resolver_v1.verify_receipt(
                receipt, project_id="PROJECT-1", project_version="1.0"
            ))
            replacement = LocalSourceEntry(
                reference=reference, source_id="SRC-001", relative_path="source.txt",
                version="v2", expected_sha256=hashlib.sha256(content).hexdigest(),
                media_type="text/plain", catalog_revision="catalog-v2",
                project_id="PROJECT-1", project_version="1.0",
            )
            resolver_v2 = LocalSourceResolver(root, {reference: replacement})
            self.assertNotEqual(resolver_v1.catalog_fingerprint, resolver_v2.catalog_fingerprint)
            self.assertFalse(resolver_v2.verify_receipt(
                receipt, project_id="PROJECT-1", project_version="1.0"
            ))

    def test_receipt_is_stale_when_source_bytes_change(self):
        with tempfile.TemporaryDirectory() as root:
            original = b"approved bytes"
            (Path(root) / "source.txt").write_bytes(original)
            reference = "local-source:source"
            resolver = LocalSourceResolver(root, {reference: entry(reference, "source.txt", original)})
            _, receipt = resolver.resolve(reference, project_id="PROJECT-1", project_version="1.0")
            (Path(root) / "source.txt").write_bytes(b"replacement bytes")
            self.assertFalse(resolver.verify_receipt(
                receipt, project_id="PROJECT-1", project_version="1.0"
            ))

    def test_cross_project_and_cross_version_resolution_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            content = b"project scoped bytes"
            (Path(root) / "source.txt").write_bytes(content)
            reference = "local-source:project-one"
            resolver = LocalSourceResolver(root, {reference: entry(reference, "source.txt", content)})
            with self.assertRaises(LocalSourceResolutionError):
                resolver.resolve(reference, project_id="PROJECT-2", project_version="1.0")
            with self.assertRaises(LocalSourceResolutionError):
                resolver.resolve(reference, project_id="PROJECT-1", project_version="2.0")

    def test_catalog_snapshot_is_not_mutable_through_resolver(self):
        with tempfile.TemporaryDirectory() as root:
            content = b"immutable catalog"
            reference = "local-source:source"
            resolver = LocalSourceResolver(root, {reference: entry(reference, "source.txt", content)})
            with self.assertRaises(TypeError):
                resolver._catalog[reference] = entry(reference, "other.txt", content)

    def test_catalog_key_must_match_entry_reference(self):
        with tempfile.TemporaryDirectory() as root:
            catalog_entry = entry("local-source:actual", "source.txt", b"x")
            with self.assertRaises(LocalSourceResolutionError):
                LocalSourceResolver(root, {"local-source:spoofed": catalog_entry})


if __name__ == "__main__":
    unittest.main()
