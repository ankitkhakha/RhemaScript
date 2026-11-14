# Approval Checkpoint Archive V1

Status: implemented as a local export/verification primitive; operational independence is not self-certifying.

## Purpose

Retain an authenticated snapshot of the approval-consumption and revocation state outside the SQLite approval database. The archive is intended to support later integrity verification and controlled recovery assessment.

## Trust boundary

The implementation provides:

- a canonical JSON envelope containing the exact approval-state snapshot; current V5 snapshots include consumed approvals, revocations and durable publish-session records; the verifier retains read compatibility with V3 and V4 snapshots;
- SHA-256 content digest and HMAC-SHA256 authentication over the archive schema, creation time, digest and encoded snapshot;
- owner-only archive file permissions (0600), an already-existing owner-owned private directory (0700 or stricter), no-follow file creation and exclusive destination creation;
- rejection of archive destinations in the same directory as the approval database;
- verification using a caller-supplied key of at least 32 bytes;
- optional byte-for-byte reconciliation against the current database snapshot.

The implementation does **not** prove that the archive directory is on independent hardware, a separate cloud account, or under separate administrative control. The operator must establish and document that separation.

## Key custody requirements

1. Generate the archive authentication key using an approved cryptographic random source.
2. Keep the key outside the approval database host and outside the archive storage location. Prefer owner-controlled offline custody or a separately administered secrets system.
3. Restrict key access to named custodians; record key identifier, custodian, creation date, rotation/revocation plan and recovery procedure without recording the key itself.
4. Never commit, email, log, or place the key in the same directory, backup, or repository as the archive.
5. Rotate keys under a documented procedure. Retain the old verification key for the full archive-retention period; do not silently re-sign old snapshots.

## Export

Create the archive directory in advance with owner-only permissions. It must be outside the SQLite database directory and should be on independently administered storage.

Example:

```python
from rhemascript.core.approval_store import SQLitePublishSessionRegistry
from rhemascript.core.approval_archive import export_checkpoint_archive

store = SQLitePublishSessionRegistry("/owner-private/db/approvals.sqlite3")
# Load this from external/offline key custody; never hardcode or commit it.
archive_key = load_archive_key_from_approved_custody()
export_checkpoint_archive(
    store,
    "/separate-controlled-archive/approval-checkpoint-2026-11-13.json",
    key=archive_key,
)
```

The destination is create-once: an existing file is never overwritten. Export failure must be investigated; do not treat an absent or partial archive as retained evidence.

## Verify and reconcile

```python
from rhemascript.core.approval_archive import verify_checkpoint_archive

result = verify_checkpoint_archive(
    "/separate-controlled-archive/approval-checkpoint-2026-11-13.json",
    key=archive_key,
    current_store=store,
)
```

Interpretation:

- `archive_valid = true`: envelope, digest, HMAC and supported V3/V4/V5 snapshot row structures verified with the supplied key; `publish_session_count` is zero for V3 and reports the validated session rows for V4/V5.
- `matches_current_state = true`: current SQLite state is byte-identical to the archived snapshot.
- `matches_current_state = false`: the archive is valid but current state differs. Preserve both states and initiate a documented reconciliation; do not overwrite either.
- `matches_current_state = null`: archive verified without a live-store comparison.

## Snapshot schema compatibility

The publish-session registry emits `RhemaScript.ApprovalStateCheckpoint.v5`, which includes the `consumed`, `revoked` and `publish_sessions` collections from one SQLite read transaction. The base approval-consumption store continues to emit V3 (`consumed` and `revoked`). The archive verifier accepts V3, V4 and V5 and validates each row before reporting `archive_valid=true`: consumed rows have 19 fields, revocation rows have 5 fields, V4 publish-session rows have 17 fields, and V5 publish-session rows have 21 fields. Validation covers scalar types, timezone-aware timestamps, credential/identity claim shape, SHA-256 values, known session states, bounded offsets, completion metadata and uniqueness constraints. These checks are structural consistency checks; they do not independently re-verify approval signatures or restore state. The archive byte limit applies on both export and verification.

## Recovery controls

This primitive intentionally does not restore or replace the live SQLite database. Recovery requires a separately approved procedure:

1. preserve the current database and archive as read-only evidence;
2. verify the archive with the correct retained key;
3. compare approval IDs, nonces, revocations, signatures and artifact bindings against independent records;
4. investigate missing, additional, conflicting or expired records;
5. require independent review and explicit owner approval before any controlled restore;
6. retain a before/after evidence record and rerun the relevant contract suite.

## Validation and limitations

Synthetic tests cover private export, populated V5 publish sessions, legacy V3 and V4 compatibility, correctly authenticated malformed-row rejection, wrong-key rejection, archive tampering, state mismatch reporting without database mutation, same-directory rejection, create-once behavior and minimum key length. CI success validates these code contracts only. It does not establish independent storage, external key custody, production retention, disaster-recovery readiness or production certification.


## Atomic read-snapshot hardening — 13 November 2026

A concurrency review found that integrity verification and checkpoint construction read related SQLite tables in separate autocommit SELECTs. Under WAL, a valid writer can commit between those reads, causing a mixed-time view (for example, readiness rows from before a commit and its event row from after it). This is a consistency defect, not evidence that an attacker can forge a valid HMAC.

The readiness registry now holds one explicit read transaction while it reads readiness rows, activity events and append-only trigger metadata for `verify()`, and while it reads both tables for checkpoint snapshot digests. The approval-consumption store likewise holds one explicit read transaction across consumed and revoked approval tables when constructing checkpoint bytes. SQLite WAL readers retain a stable snapshot while concurrent writers commit; this behavior is documented by SQLite: https://www.sqlite.org/isolation.html.

Adversarial interleaving tests arrange a real second-connection commit after the first table has been read. They assert that the in-flight verification/checkpoint snapshot remains internally consistent and that the concurrent commit is visible to a subsequent read. This does not replace independent HMAC checkpoint custody, and it does not make local SQLite storage tamper-proof.


## Generation-bound archives and independent freshness-anchor contract

A generation-bound archive uses `RhemaScript.ApprovalCheckpointArchive.v2`. Its monotonically increasing integer generation is included inside the HMAC-authenticated envelope alongside the snapshot digest. V1 archives remain verifiable for historical purposes but have no generation and cannot be registered as a current production recovery point.

The candidate now defines `rhemascript/core/checkpoint_freshness.py`:
- `MonotonicCheckpointAnchor` requires an independently administered adapter with authenticated, linearizable `read_latest` and atomic compare-and-advance operations;
- `advance_checkpoint_anchor` verifies the archive bytes and HMAC itself before attempting an exact next-generation append, then reads the record back and checks generation and digest;
- `verify_checkpoint_against_anchor` cryptographically verifies the archive and requires its generation and digest to match the independently retained latest record; it also rejects stale or future-dated anchor-read responses;
- generation conflicts, missing anchors, stale archives, digest mismatches and archive-authentication failures fail closed.

Synthetic tests exercise exact-generation registration, read-back, stale-archive rejection, compare-and-advance conflict, wrong archive key and skipped-generation rejection. The fake anchor is test-only. No network service, hardware monotonic counter, separate account, external append-only log or independent administrator is implemented. The protocol contract does not make a local adapter independent by itself. **Scope limitation:** the current V2 generation-bound archive covers the approval-consumption/revocation SQLite store only. The RAEI readiness registry currently exports a separate HMAC checkpoint (schema `rhemascript-registry-checkpoint-v2`) without a generation field or archive bundle. A production recovery anchor for the complete system must bind a composite manifest containing both the approval-store snapshot digest and the readiness-registry snapshot/event-head digest (plus any other authoritative state stores) to one generation, or maintain separately coordinated monotonic anchors with a documented consistency protocol. The current helper does not yet provide that composite bundle or prove cross-store atomicity.

## Anti-rollback and freshness boundary

The archive's authenticated `created_at` value is a signed timestamp, not a monotonic sequence or an independently trusted freshness proof. `verify_checkpoint_archive` proves that the supplied archive is internally authentic; with `current_store`, it reports whether that archive matches the current database snapshot. It cannot determine whether a newer valid archive exists elsewhere, and it cannot detect a coordinated rollback in which an older database snapshot and its matching older archive are both replayed.

The readiness-registry HMAC checkpoint has the same fundamental limitation: verification is relative to the exact checkpoint object and key supplied by the caller. A valid old checkpoint remains valid for the old state it describes.

Before production recovery is approved, an independent anti-rollback anchor is required. It must retain at least a monotonically increasing checkpoint generation and the corresponding snapshot digest in a separately administered append-only or hardware-backed system. Recovery must compare the candidate archive against that latest trusted anchor before any restore is considered. No such monotonic anchor is implemented or claimed by this repository.

## Approval expiry under database contention — 13 November 2026

A review of the durable single-use approval store identified a time-of-check/time-of-use edge case: a credential could pass its expiry check before opening the SQLite write transaction, wait behind another writer, and then be committed after expiry. The store now repeats the expiry check after `BEGIN IMMEDIATE` succeeds and uses that post-lock timestamp for `consumed_at`. A deterministic regression test holds a competing writer lock beyond the credential's expiry and asserts that the approval is not consumed. The pre-lock check remains as a fast rejection; the post-lock check is authoritative for the commit.
