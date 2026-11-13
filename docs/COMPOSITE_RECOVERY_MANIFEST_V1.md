# Composite Recovery Manifest V1

## Purpose

Bind the two currently authoritative local state stores into one generation-bound recovery record:

1. The approval-consumption and revocation SQLite store, represented by its V2 generation-bound approval archive.
2. The RAEI readiness registry, represented by its signed readiness checkpoint (including readiness records and the activity-event chain head).

The composite manifest binds the exact approval archive file digest, approval snapshot digest, readiness checkpoint, readiness checkpoint digest, common generation, and a separate HMAC-SHA256. The digest of the complete manifest can be registered with the existing independent monotonic checkpoint-anchor contract.

## Implementation

Module: `rhemascript/core/composite_checkpoint.py`

Public operations:

- `export_composite_checkpoint_manifest(...)`: verify the generation-bound approval archive against the current approval store, capture both store checkpoints twice, abort if either changes, then write a create-once private manifest.
- `verify_composite_checkpoint_manifest(...)`: verify the manifest HMAC, exact approval archive bytes, approval archive signature and live approval state, and readiness checkpoint against the live readiness registry. It rechecks both stores for stability during verification.
- `advance_composite_checkpoint_anchor(...)`: register the composite manifest's SHA-256 digest at the existing monotonic anchor, using exact next-generation compare-and-advance and read-back.
- `verify_composite_checkpoint_against_anchor(...)`: require the manifest generation and exact digest to match the latest independent anchor record.

The manifest and archive files are opened without following symlinks, bounded, required to be owner-owned and private, and created exclusively without overwriting an existing record.

## Key separation and custody

Use four distinct keys with at least 32 bytes of key material:

- approval-store checkpoint key;
- readiness-registry checkpoint key;
- approval archive key;
- composite-manifest key.

Keys must not be committed, logged, stored alongside the databases or archives, or shared across trust domains without a documented key-management decision. Production key custody remains an external operational dependency. Synthetic test keys are test fixtures only.

The independent monotonic anchor must be administered outside the application/database trust boundary. The in-memory fake anchor in tests is not a production adapter and does not establish independent custody.

## Capture consistency

SQLite does not provide one transaction spanning two independent database files. The exporter therefore captures each checkpoint before and after archive reconciliation and refuses to produce a manifest if either checkpoint changes. It also rechecks the archive bytes and archive verification.

This double-sampling detects ordinary concurrent writes during the capture window. It is not a distributed transaction, does not defeat a malicious same-owner process able to rewrite all local state and keys, and does not prove the absence of every adversarial timing attack. A formal production backup must quiesce writes across both stores for the capture window or use a separately reviewed coordinated snapshot protocol. The operational record must identify the quiescence procedure and owner.

## Recovery boundary

This implementation is verification/export only. It does not:

- restore, overwrite, replace, or roll back either SQLite database;
- infer which store is authoritative when the manifest and live stores disagree;
- implement an external anchor service, HSM/KMS, independent cloud account, or separate administrator;
- prove production key custody, retention, availability, or disaster-recovery RTO/RPO.

If any digest, generation, HMAC, archive, checkpoint, or anchor check fails, preserve all observed files and databases as evidence, stop writes, and require independent reconciliation. Do not attempt automatic repair or restore.

## Tests and evidence

`tests/test_composite_checkpoint.py` covers:

- successful binding of both stores and the exact approval archive;
- wrong manifest key;
- altered approval archive;
- changed readiness state;
- changed approval state;
- private create-once manifest behavior;
- independent anchor registration/read-back;
- modified/stale manifest rejection.

CI success validates code and synthetic test behavior only. It does not certify production recovery or the independent anchor deployment.

## Release gates

Before production use:

1. Deploy an authenticated, linearizable monotonic anchor under independent administration.
2. Establish distinct external key custody and rotation/revocation procedures.
3. Define and rehearse a write-quiescence or coordinated snapshot procedure.
4. Perform restore drills on isolated copies, never against production databases.
5. Obtain independent security review of the composite protocol, path handling, key lifecycle, anchor adapter, and restore runbook.
6. Record measured recovery-point and recovery-time objectives and verify them in a witnessed exercise.
