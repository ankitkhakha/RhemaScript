# IF-18 Audit Storage — Segmented JSONL and Bounded Lookup Design (Draft V1)

**Status:** Design proposal only — not implemented, not approved for retention/destruction changes  
**Candidate:** PR #70  
**Baseline source:** `rhemascript/integrations/audit.py` at `218a51f378c9c01573dcae051e792e910eabe50d`  
**Related observation:** `OBS-PR70-004`  
**Owner decision required:** retention period, archive authority, maximum total storage, and behavior when capacity is exhausted

## 1. Problem statement

The current `JsonlAuditSink.__call__` acquires the per-instance thread lock and file-level POSIX exclusive lock, checks the final newline, then reads, parses and schema-validates every existing JSONL record before every append. This preserves fail-closed behavior but makes append work proportional to total history. Across N appends, repeated full-history scans approach O(N²) cumulative work. The scan also has no explicit maximum line length, record count, or file size.

Completion-event idempotency currently depends on searching the full log for a matching `completion_event_id`. Any optimization must preserve cross-process deduplication, conflicting-identity detection, and recovery of a previously visible record whose earlier fsync failed.

## 2. Non-negotiable invariants

1. **Evidence preservation:** no automatic deletion, truncation, compaction, or rewrite of historical audit rows.
2. **Fail closed:** malformed JSON, invalid schema, incomplete tails, unsupported segment metadata, or index/log disagreement must never be treated as a clean audit history.
3. **Durability ordering:** append bytes, fsync the segment file, then fsync the pinned containing directory before reporting durable success.
4. **Cross-process serialization:** all writers and rotation/recovery operations coordinate through a stable lock protocol, not only an in-process mutex.
5. **Stable idempotency:** the same completion ID and same result is accepted as a duplicate; the same ID with a different project/request/status/resource identity is rejected.
6. **No secret-bearing content:** retain the existing metadata-only event schema and redaction contract.
7. **Portable fail-closed behavior:** if required directory-descriptor, locking, or durable-index primitives are unavailable, reject the operation rather than silently weakening guarantees.
8. **Legacy continuity:** the current unversioned legacy schema and schema v1 remain readable; any later schema requires an explicit compatibility rule.

## 3. Proposed storage layout

Use one private directory (owner-only permissions) containing:

- `audit.lock` — stable lock inode opened without following symlinks; held exclusively across append, rotation, index update, and recovery.
- `manifest.json` — versioned ordered list of segment IDs, names, byte lengths, record counts, first/last sequence numbers, and sealed state. Replace atomically using write-temp, fsync-temp, rename-relative-to-pinned-dir, fsync-directory.
- `segments/segment-<monotonic-sequence>.jsonl` — append-only active segment plus immutable sealed segments. Segment names are generated internally; never accept caller paths.
- `completion-index.sqlite3` — rebuildable lookup index mapping completion ID to immutable segment ID, byte offset, record length, and canonical result identity. The index is an accelerator, never the source of truth.

Do not place bearer URLs, credentials, payloads, or raw provider response bodies in the manifest or index.

## 4. Bounded append algorithm

1. Validate the incoming event with the existing schema-v1 validator and encode it once. Reject a serialized row above a configured hard maximum (proposal: 64 KiB); the final value must be checked against actual maximum supported event metadata.
2. Open and pin the storage directory and stable lock file using no-follow, descriptor-relative operations. Acquire the process lock and an in-process lock.
3. Load and validate the manifest. Reject unknown manifest versions, unsafe segment names, non-monotonic sequence ranges, duplicate segment IDs, or missing referenced files.
4. Validate the active segment's final newline and bounded tail. A partial final row is not silently truncated. Quarantine/stop and require an explicit recovery procedure that preserves the original bytes.
5. For a completion event, query the durable completion index while holding the global lock. If an entry exists, read exactly the referenced bounded row from its segment and revalidate it from source. Compare request/project/status/resource identity. A matching COMPLETED row is a duplicate; a matching INDETERMINATE row may be followed by its permitted completion recovery; a conflicting identity fails closed. Never trust index metadata without validating the referenced source row.
6. If the active segment would exceed a proposed cap (64 MiB or 100,000 rows, whichever occurs first), seal it and create the next segment. These are starting design values, not approved operational limits.
7. Append the complete encoded row to the active segment, handling short writes. Fsync the segment, then fsync the pinned segment directory.
8. Insert/update the completion index in a SQLite transaction with durable settings (e.g. synchronous FULL). Commit only after the source JSONL row is durable. The index is rebuildable: if a crash occurs after JSONL fsync but before index commit, recovery replays and validates the missing source tail before the index is trusted.
9. Update the manifest only when segment state changes (creation/seal), using atomic replacement and directory fsync. Return success only after all required durability steps have succeeded.

### Index trust and rebuild

The JSONL segments remain authoritative. On startup, index metadata must be checked against manifest generation and the segment high-water marks. If the index is absent, behind, corrupt, or inconsistent, rebuild it by scanning and validating the segments once in sequence order. Until rebuild completes, completion deduplication must not proceed from a partial index.

For normal operation, retain a durable checkpoint of the last fully indexed segment/offset and replay only bytes after that checkpoint. Checkpoint advancement must occur only after all preceding rows have been indexed and the SQLite transaction has committed. If checkpoint integrity cannot be established, perform a full rebuild or fail closed. A checkpoint is an optimization, not permission to skip source validation.

## 5. Rotation and crash recovery

Rotation is serialized under the same stable lock:

- Seal current segment only after its last row and file fsync are complete.
- Create the next segment with exclusive creation and restrictive permissions.
- Fsync the new segment and containing directory.
- Atomically publish the updated manifest and fsync the directory.
- Never unlink or overwrite a prior segment during rotation.

Crash cases:

| Crash point | Recovery behavior |
|---|---|
| Before append | No new row; retry is safe |
| During row write | Unterminated tail detected; fail closed and preserve bytes for explicit recovery |
| After row write, before file fsync | Durability unknown; inspect source, validate complete row/tail, then rebuild index; do not assume absent |
| After file fsync, before directory fsync | File data may be durable but entry durability is uncertain; re-sync pinned directory and reconcile |
| After JSONL+directory fsync, before index commit | Source row is authoritative; replay from checkpoint and rebuild index |
| After index commit, before caller receives success | Retry resolves through source-validated index entry |
| During segment creation / manifest replacement | Reconcile directory contents against last valid manifest; unknown orphan segments are preserved and require deterministic recovery, not deletion |
| During archive/retention operation | No source deletion in the baseline design; archive copy must be verified before any separately approved retirement |

## 6. Retention and capacity policy — deliberately unresolved

Segmentation bounds per-append scan and per-file size; it does **not** bound total disk usage. Do not imply otherwise.

Before implementing any deletion or archival retirement, obtain explicit approval for:

- minimum retention duration and any legal/audit hold;
- whether archive storage is permitted, where it lives, encryption/access controls, and verification requirements;
- maximum total storage and behavior when the cap is reached;
- whether the system must fail closed, pause provider writes, or require operator intervention at capacity;
- backup/restore and disaster-recovery expectations;
- whether historical completion IDs must remain deduplicated for the lifetime of the project.

Safe default pending that decision: keep every sealed segment, alert on capacity thresholds, and fail closed before any destructive action. Never silently prune the completion index or its source records.

## 7. Resource bounds and operational metrics

Proposed initial tunables for benchmark and review (not approved production defaults):

- maximum encoded row: 64 KiB;
- active segment rollover: 64 MiB or 100,000 records;
- maximum manifest size: 1 MiB;
- bounded index lookup by primary key on completion ID;
- bounded record read by indexed byte offset and length;
- configurable warning thresholds at 70% and 85% of approved storage capacity.

Measure append p50/p95/p99, lock wait time, segment rollover duration, index rebuild time, bytes scanned during recovery, index hit/miss, schema rejection counts, and storage-capacity headroom. Metrics must not include sensitive event values.

## 8. Required test matrix before implementation acceptance

- Append to empty, active, and sealed-segment histories.
- Concurrent multi-process append and completion retries during ordinary writes and rotation.
- Duplicate completion ID with identical result; same ID with conflicting project, request, status, or resource.
- INDETERMINATE followed by matching COMPLETED recovery; repeated recovery.
- Index absent, stale, corrupt, truncated, wrong generation, and maliciously inconsistent offset.
- Crash injection at every ordering boundary in sections 4 and 5.
- Unterminated tail, oversized line, malformed UTF-8/JSON, invalid legacy row, unsupported schema version, missing segment, extra unreferenced segment.
- Symlinked storage path, replaced parent directory, permissions/ownership drift, descriptor lifecycle and lock-file replacement.
- Segment cap by bytes and record count; oversized single event; manifest cap.
- Archive copy verification and no-delete behavior before retention approval.
- Performance test showing steady-state append does not scan all historical bytes and completion lookup remains bounded as segment count grows.
- Restore test proving manifest/index reconstruction from preserved JSONL source segments.

## 9. Implementation phases and gates

**Phase A — design approval:** agree retention/capacity policy, archive model, lock ownership, row/segment bounds, and whether SQLite index dependency is acceptable.

**Phase B — read-only prototype:** implement a verifier/rebuilder over copied synthetic segment fixtures; no writer cutover, no mutation of existing logs, no deletion.

**Phase C — shadow index:** build and compare completion lookup results against the current full-log scan on synthetic fixtures; retain the full scan as oracle. No production data writes.

**Phase D — candidate writer:** add segment writer behind explicit opt-in/configuration; preserve existing single-file sink behavior by default until compatibility and migration are approved.

**Phase E — controlled migration:** copy existing log to immutable segment zero, verify byte-for-byte hash and record count, build index, compare every completion key and schema outcome, then require explicit operator approval to switch paths. Preserve original file.

**Phase F — retention:** separate approval and design. No automatic deletion in Phases A–E.

## 10. Decision record

| Decision | Proposed position | State |
|---|---|---|
| Source of truth | Immutable JSONL segments | Proposed |
| Completion lookup | Rebuildable SQLite index, source-row verification on every hit | Proposed |
| Writer coordination | Stable directory-relative lock file + process mutex | Proposed |
| Segment bounds | 64 MiB / 100,000 records | Benchmark/review required |
| Maximum row | 64 KiB | Validate against event contract |
| Retention | No deletion; preserve all sealed segments | Safe default pending approval |
| Capacity exhaustion | Fail closed and require operator action | Approval required |
| Existing single-file log migration | Copy/verify, retain original, explicit opt-in cutover | Not authorized |
| Production/live provider use | Out of scope | Not authorized |

## 11. Current evidence and limitations

At baseline `218a51f`, the sink validates the entire existing file on every append while holding the file lock. It uses POSIX `flock`, file fsync, pinned-parent directory fsync, and strict event schema validation. Exact-head synthetic CI has validated the preceding append, path-anchoring, schema-version and metadata-validation changes. This design document does not establish a benchmark, production storage requirement, retention authority, or operational approval.

**No code path, storage format, retention policy, or live provider behavior is changed by this document.**
