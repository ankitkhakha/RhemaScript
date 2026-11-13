# RAEI Field Intelligence & Continuous R&D Engine V1.0

**Status:** Working implementation candidate on the PR #45 feature branch. Current implementation candidate includes the optional V3 authenticated submitter capture path and consumed-approval capability enforcement; exact-head CI run #1363 passed on code/test head `4af72f8812b291c2530f2471a5f5fd9c933dde29`. Production identity adapters remain unimplemented.  
**Purpose:** Preserve creator observations, investigate them with evidence, and connect findings to research, decisions, requirements, implementation, tests and learning.  
**Authority:** No new approval gate. The Human Director retains existing decision and execution authority.

## 1. Architecture reconciliation and inheritance decision

The repository review identified three relevant existing components:

1. `rhemascript/evidence/readiness_registry.py` is the current PR #45 SQLite registry for durable readiness, knowledge and training records. It binds records to exact evidence hashes, rejects replay with changed content, verifies evidence files and supports independently retained HMAC checkpoints.
2. `rhemascript/evidence/artifact_verification.py` includes an in-memory hash-chain `IntegrityLedger`; it is not a durable cross-session activity ledger.
3. PR #38 contains an earlier append-only JSON learning ledger with a hash chain, but PR #38 remains draft/open/unmerged and is 40 commits behind current `main`. It is a separate learning-progress store and is not the current PR #45 persistence architecture.

**Decision:** Do not merge PR #38 wholesale and do not create a second parallel ledger. Port the useful append-only hash-chain concept into the existing SQLite `ReadinessRunRegistry` as an `activity_events` table. Readiness, training and knowledge writes automatically create events in the same database transaction. Field findings and later decision/change/test events use the same event history.

The provider `JsonlAuditSink` remains a separate metadata-only provider-gateway audit sink. It is not repurposed to store creator observations or the full RAEI work history.

## 2. Event history contract

The existing SQLite database now contains:
- `readiness_runs` — existing immutable readiness/knowledge/training records with exact payload hashes;
- `activity_events` — append-only ordered events with unique event IDs, event type, project/subject IDs, canonical payload JSON, payload SHA-256, predecessor hash, event hash and UTC record time.

Event-chain properties:
- sequence starts at 1 and must be contiguous;
- first predecessor is `GENESIS`;
- each event hash binds the full canonical event body and predecessor hash;
- payload JSON must be canonical and its SHA-256 must match;
- duplicate event IDs are idempotent only when the entire event content is identical; changed replay is rejected;
- SQLite triggers reject ordinary UPDATE and DELETE operations;
- registry verification checks the chain and confirms every readiness record has exactly one corresponding readiness/import event;
- HMAC checkpoint V2 covers readiness record count, event count, complete registry digest and event-chain head;
- V1 readiness checkpoints remain verifiable only where no activity events exist;
- older readiness rows without an event chain are imported through explicitly labelled `LEGACY_READINESS_RECORD_IMPORTED` events, retaining their original record timestamp in the event payload.

A hash chain detects internal edits, gaps and predecessor changes. It does not by itself prevent a privileged actor from rewriting the whole database and recomputing the chain. Independent retention of the HMAC checkpoint is required to detect wholesale history replacement or truncation.

## 3. Event vocabulary

The registry reserves event types for:
- `READINESS_RUN_RECORDED`, `LEGACY_READINESS_RECORD_IMPORTED`;
- `FINDING_CAPTURED`, `FINDING_RESEARCHED`, `FINDING_REPRODUCED`, `FINDING_DISPOSITIONED`, `FINDING_PLANNED`, `FINDING_IMPLEMENTED`;
- `DECISION_RECORDED`, `REQUIREMENT_RECORDED`, `CHANGE_RECORDED`, `TASK_RECORDED`;
- `IMPLEMENTATION_RECORDED`, `TEST_RECORDED`, `DEFECT_RECORDED`, `LESSON_RECORDED`, `HANDOVER_RECORDED`.

Only implemented event operations may be submitted. The vocabulary does not imply that all future transitions or interfaces already exist.

## 4. Field finding intake V1

The initial operator workflow is available through the RAEI CLI; a graphical “Capture Finding” surface is not yet implemented.

A finding is submitted as a versioned JSON evidence artifact using schema `raei-field-finding-v1`. Start from `templates/raei-field-finding.template.json` and replace every placeholder before verification. Do not include passwords, access tokens or other secrets; if sensitive content must be redacted, document that redaction in `redaction_note` while preserving the remaining original wording. Required fields include:
- finding ID and version;
- project ID;
- title and original observation wording;
- affected workflow;
- expected and observed behaviour;
- impact and reproduction steps;
- supporting evidence references;
- exact primary evidence ID/version and timestamp.

The service:
1. verifies the exact primary artifact bytes and their evidence ID/version;
2. validates the strict finding schema and rejects caller-supplied status, approval or evidence-grade fields;
3. verifies each supplied supporting artifact using the existing safe artifact verifier;
4. records exact evidence IDs, paths, versions, SHA-256 digests and byte sizes;
5. appends a `FINDING_CAPTURED` event to the shared registry;
6. starts every finding at `SUBMITTED`, with identity authentication `UNVERIFIED`, source authentication `NOT_CHECKED` and claim relevance `NOT_ASSESSED`.

The original observation remains in the exact versioned finding artifact. The event stores a hash-bound reference and key structured metadata; it does not silently rewrite the creator's words.

### Evidence suggestions

The intake service may suggest:
- E0 — no reproduction steps or supporting artifact supplied;
- E1 — a detailed reported account includes reproduction steps;
- E2 — one or more supporting artifacts are present and their bytes can be verified.

These are intake suggestions only. They do not prove the observation is true, the source is authentic, the artifact is relevant or the issue is reproduced. E3 requires an independently recorded reproduction; E4 requires authoritative documentation/source verification. The current intake leaves evidence assessment `NOT_ASSESSED`.

### Current status and authority boundary

The default local CLI capture remains unverified unless a trusted V3 submitter credential is supplied through the authenticated capture API. The authenticated API requires a V3 `FINDING_SUBMIT` credential bound to the exact observation evidence ID/version/SHA-256/size, project version and request ID. The registry records actor ID from the verified directory-derived approval, issuer-scoped subject, role, authentication context/time, session, policy/provider IDs and approval fingerprint. Generic event append cannot forge the verified identity fields. The approval must have passed atomic replay consumption before the registry accepts it.

The default CLI still records `UNVERIFIED` submitter identity. Authenticated research and reproduction transitions are available through typed APIs in `raei/finding_lifecycle.py`: each requires a V3 approval bound to the exact report artifact; reproduction requires prior research and a different human subject and session in the same trusted identity domain. The exact report schemas are provided in `templates/raei-finding-research.template.json` and `templates/raei-finding-reproduction.template.json`. Generic event append cannot forge these transitions. There is not yet a CLI command for these APIs. Governed finding disposition is a separate two-approval transition with exact evidence lineage. Authenticated planning is implemented and requires prior research, an independently authenticated REPRODUCED outcome, an ACCEPTED governed disposition, and a planner distinct from the submitter, researcher and reproducer. Authenticated implementation is now implemented in the candidate through `FINDING_IMPLEMENTED`: it binds the exact plan event and plan evidence tuple, verifies its own report bytes, requires a consumed V3 `FINDING_IMPLEMENT` approval, enforces separation from submitter/researcher/reproducer/planner identities, and projects the `IMPLEMENTED` state. Exact-head CI run #1446 passed on `5a34e7110d04f7693f50a6d559120e491d27698a`. Independent effectiveness assessment is now implemented in the candidate through `FINDING_EFFECTIVENESS_ASSESSED`: it binds the exact implementation event/evidence tuple, requires a consumed V3 `FINDING_EFFECTIVENESS_ASSESS` approval, enforces assessor separation from all prior lifecycle participants, and projects `EFFECTIVE`, `INEFFECTIVE` or `INCONCLUSIVE`. Exact-head CI run #1458 passed on `0771e284a751abebedaf657b9bacf170eddfe10d`. Two-person governed closure is now implemented through `FINDING_CLOSED`: both V3 approvals bind the exact effectiveness evidence; reviewers must be distinct subjects and sessions, independent of all prior lifecycle participants, and share the trusted provider/policy domain. Closure is permitted only for an `EFFECTIVE` assessment and binds the exact plan, implementation and effectiveness event IDs. The finding projection exposes `CLOSED`. Exact-head CI run #1482 passed on `eb15d2fd02b6fff18676d874db4041652d450a9d`. Reopening remains an open lifecycle stage. Closed-finding knowledge inheritance is now implemented through `inherit_closed_finding_as_knowledge` and source type `RAEI_CLOSED_FINDING`: it requires a CLOSED finding, EFFECTIVE assessment, and exact plan/implementation/effectiveness/closure event and evidence lineage. Inherited knowledge is always recorded as `PENDING_REVIEW`, `UNVERIFIED`, source authentication `NOT_CHECKED` and claim relevance `NOT_ASSESSED`; lineage is revalidated on every knowledge read. Exact-head CI run #1498 passed on `d3d854d0ec7dd2a7471526de6f973bf513e54909`. Proposed transition contracts and evidence templates are documented in `docs/RAEI_CONTROLLED_IMPLEMENTATION_EFFECTIVENESS_CLOSURE_LEARNING_CONTRACT_V1.md`, `templates/raei-finding-implementation.template.json` and `templates/raei-finding-effectiveness.template.json`; these are governance/evidence-shape artifacts, not implemented APIs. Existing governed disposition is still a separate transition and is not yet forced to wait for research/reproduction. Source authentication and claim relevance remain separately unassessed. This intake does not approve a requirement, authorize a code change, consume credits, connect a Google account, generate media, upload or publish.

## 5. Operator commands

Initialize the private local registry using the existing procedure:

```bash
python -m raei init --database <private-path>/learning.sqlite3
```

Capture a finding artifact:

```bash
python -m raei capture-finding --database <private-path>/learning.sqlite3 --evidence-root <evidence-root> --artifact-path findings/RS-FND-001.json
```

List findings:

```bash
python -m raei finding-list --database <private-path>/learning.sqlite3 --evidence-root <evidence-root> --project-id RS-PWW-001
```

The existing `verify`, `status`, `next`, `brief`, `knowledge-search`, `record-attempt` and `record-knowledge` commands remain in place.

## 6. Relationship to BWSF and biblical foundation

BWSF's Solomon study provides a carefully labelled application: receive the creator's observation accurately before diagnosing it. The system must preserve the original wording, expected/observed behaviour, context and evidence; then investigate rather than dismiss or automatically accept it.

This is a modern operational analogy, not a claim that an AI has a human heart, consciousness or spiritual discernment. The biblical meaning of 1 Kings 3 remains Solomon's God-given capacity to hear, judge and govern God's people justly.

## 7. Acceptance tests

- Exact primary finding bytes, evidence ID, version, SHA-256 and size are bound.
- Supporting evidence must exist and match its recorded bytes.
- Missing or altered evidence blocks verification.
- Same finding ID/version and same bytes is idempotent; changed content under the same identity is rejected.
- Findings start as `SUBMITTED`, not approved or verified.
- Suggested evidence level never changes source-authentication or claim-relevance status.
- Activity events are sequence- and hash-chain-verified.
- Ordinary event update/delete is rejected; simulated tampering is detected.
- External HMAC checkpoint detects event-history truncation.
- Readiness records and events remain consistent; legacy readiness records are explicitly imported.
- Backup/restore preserves event chain and checkpoint verification.
- Existing knowledge and training records remain readable and retain their evidence bindings.

## 8. Implementation boundaries and remaining work

**Implemented in this candidate:** persistent activity event table, event hash chain, idempotent event IDs, readiness-event binding, legacy readiness import, HMAC checkpoint V2, event-linked evidence re-verification, finding artifact validation, CLI capture/list operations and synthetic regression tests.

**Still outstanding:** exact-head CI for the latest candidate; operational operator acceptance; a graphical capture surface; finding research/reproduction/disposition transitions; authenticated actor identity and signed decision/approval binding; independently retained checkpoint operations; local deployment/backup procedure; full reconciliation with the Control Centre registers and the final application UI.

The existing main branch is not modified. PR #45 remains draft/open/unmerged. No live provider connection, external write, media generation, credit use, upload or publishing is performed.
