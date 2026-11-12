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


def entry(reference: str, path: str, content: bytes) -> LocalSourceEntry:
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

    def test_catalog_key_must_match_entry_reference(self):
        with tempfile.TemporaryDirectory() as root:
            catalog_entry = entry("local-source:actual", "source.txt", b"x")
            with self.assertRaises(LocalSourceResolutionError):
                LocalSourceResolver(root, {"local-source:spoofed": catalog_entry})


if __name__ == "__main__":
    unittest.main()
