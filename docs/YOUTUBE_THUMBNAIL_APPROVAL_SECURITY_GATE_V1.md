# YouTube Thumbnail Approval Security Gate V1

## Finding

The thumbnail write path reused the two V3 approvals (FINAL_ACCEPTANCE and PUBLISH) that are cryptographically bound to the final-film artifact. Those credentials did not bind the thumbnail image bytes, their digest or size. The provider gateway therefore could not establish that the thumbnail being sent was the exact thumbnail independently reviewed and approved.

The prior file checks (PNG/JPEG extension, non-empty content and a 2 MiB limit) are input validation, not approval of the exact content. A successful video read-back also does not approve a later thumbnail payload.

## Immediate control

Thumbnail writes are disabled in both the YouTube client and IF-18 external gateway. The client rejects the operation before consuming final-film approvals or reading the supplied path. The gateway independently rejects THUMBNAIL_WRITE before transport, so a caller cannot bypass the client guard by invoking IF-18 directly.

This is an intentional fail-closed capability restriction. It does not affect final-film upload or read-only YouTube operations.

## Requirements before re-enabling

A separately reviewed implementation must provide all of the following:

1. A dedicated signed thumbnail approval action and credential schema (or a rigorously specified multi-artifact claim) that binds project ID/version, request ID, target YouTube video ID, thumbnail artifact ID/version, SHA-256 digest and exact byte length.
2. Two distinct authorized human subjects and identity sessions, with the existing issuer, identity-policy, expiry, key-status and replay-consumption controls.
3. Safe no-follow file opening, descriptor-based regular-file validation, bounded reading and digest verification against the signed thumbnail claim.
4. Gateway-side independent verification of the consumed thumbnail-specific approval pair, target video, project/version, request and exact request-body digest/length immediately before provider transport.
5. Adversarial tests for altered bytes after approval, symlink substitution, wrong video ID, wrong project/version, replayed IDs/nonces, cross-project substitution, stale/revoked signing keys and proof that every rejection occurs before network transport.
6. Exact-head CI, independent human security review and an updated operational approval runbook.

No thumbnail provider write is authorized by this document. No live Google authorization is required for the synthetic tests of this block.
