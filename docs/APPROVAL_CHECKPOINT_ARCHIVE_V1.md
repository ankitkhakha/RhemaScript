# Approval Checkpoint Archive V1

Status: implemented as a local export/verification primitive; operational independence is not self-certifying.

## Purpose

Retain an authenticated snapshot of the approval-consumption and revocation state outside the SQLite approval database. The archive is intended to support later integrity verification and controlled recovery assessment.

## Trust boundary

The implementation provides:

- a canonical JSON envelope containing the exact V3 approval-state snapshot;
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
from rhemascript.core.approval_store import SQLiteApprovalConsumptionStore
from rhemascript.core.approval_archive import export_checkpoint_archive

store = SQLiteApprovalConsumptionStore("/owner-private/db/approvals.sqlite3")
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

- `archive_valid = true`: envelope, digest, HMAC and V3 snapshot structure verified with the supplied key.
- `matches_current_state = true`: current SQLite state is byte-identical to the archived snapshot.
- `matches_current_state = false`: the archive is valid but current state differs. Preserve both states and initiate a documented reconciliation; do not overwrite either.
- `matches_current_state = null`: archive verified without a live-store comparison.

## Recovery controls

This primitive intentionally does not restore or replace the live SQLite database. Recovery requires a separately approved procedure:

1. preserve the current database and archive as read-only evidence;
2. verify the archive with the correct retained key;
3. compare approval IDs, nonces, revocations, signatures and artifact bindings against independent records;
4. investigate missing, additional, conflicting or expired records;
5. require independent review and explicit owner approval before any controlled restore;
6. retain a before/after evidence record and rerun the relevant contract suite.

## Validation and limitations

Synthetic tests cover private export, wrong-key rejection, archive tampering, state mismatch reporting without database mutation, same-directory rejection, create-once behavior and minimum key length. CI success validates these code contracts only. It does not establish independent storage, external key custody, production retention, disaster-recovery readiness or production certification.
