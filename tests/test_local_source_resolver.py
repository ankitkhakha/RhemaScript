from __future__ import annotations

import hashlib
import unittest

from rhemascript.evidence.local_source_resolver import (
    LocalSourceEntry,
    LocalSourceResolutionError,
    LocalSourceResolver,
)


def _entry(reference: str, path: str, content: bytes) -> LocalSourceEntry:
    return LocalSourceEntry(
        reference=reference,
        source_id="SRC-001",
        relative_path=path,
        version="v1",
        expected_sha256=hashlib.sha256(content).hexdigest(),
        media_type="text/plain",
        catalog_revision="catalog-v1",
    )


def test_resolves_exact_catalogued_reference_and_only_claims_content_identity(tmp_path):
    content = b"Approved local source bytes"
    (tmp_path / "source.txt").write_bytes(content)
    reference = "local-source:scripture-corpus:GEN-1-1"
    resolver = LocalSourceResolver(str(tmp_path), {reference: _entry(reference, "source.txt", content)})

    evidence, receipt = resolver.resolve(reference)

    assert evidence.sha256 == hashlib.sha256(content).hexdigest()
    assert receipt.outcome == "CONTENT_VERIFIED"
    assert receipt.source_authentication == "NOT_CHECKED"
    assert receipt.claim_relevance == "NOT_CHECKED"
    assert receipt.original_reference == reference


def test_unknown_reference_is_rejected(tmp_path):
    reference = "local-source:unknown"
    resolver = LocalSourceResolver(str(tmp_path), {
        "local-source:known": _entry("local-source:known", "source.txt", b"x")
    })
    with unittest.TestCase().assertRaises(LocalSourceResolutionError):
        resolver.resolve(reference)


def test_changed_bytes_fail_catalog_digest_check(tmp_path):
    (tmp_path / "source.txt").write_bytes(b"substituted")
    reference = "local-source:approved"
    resolver = LocalSourceResolver(str(tmp_path), {
        reference: _entry(reference, "source.txt", b"original")
    })
    with unittest.TestCase().assertRaises(LocalSourceResolutionError):
        resolver.resolve(reference)


def test_path_traversal_is_rejected(tmp_path):
    reference = "local-source:traversal"
    resolver = LocalSourceResolver(str(tmp_path), {
        reference: _entry(reference, "../outside.txt", b"x")
    })
    with unittest.TestCase().assertRaises(LocalSourceResolutionError):
        resolver.resolve(reference)


def test_symlink_is_rejected(tmp_path):
    outside = tmp_path.parent / "outside-source.txt"
    outside.write_bytes(b"source")
    link = tmp_path / "source-link.txt"
    link.symlink_to(outside)
    reference = "local-source:symlink"
    resolver = LocalSourceResolver(str(tmp_path), {
        reference: _entry(reference, "source-link.txt", b"source")
    })
    with unittest.TestCase().assertRaises(LocalSourceResolutionError):
        resolver.resolve(reference)


def test_catalog_key_must_match_entry_reference(tmp_path):
    entry = _entry("local-source:actual", "source.txt", b"x")
    with unittest.TestCase().assertRaises(LocalSourceResolutionError):
        LocalSourceResolver(str(tmp_path), {"local-source:spoofed": entry})
