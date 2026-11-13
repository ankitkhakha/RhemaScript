# RAEI Continuous Learning Engine V1.0

## Purpose

The RAEI learning engine turns the approved mastery programme into a versioned curriculum, practical tasks, evidence-linked assessments and controlled progress records. It does not claim that adding documents or assessment records retrains the underlying ChatGPT model weights.

## Architecture

- **Curriculum registry:** ordered units across computer science, full-stack engineering, AI/ML and agent systems, whole-Bible literacy, Bible-only ethics, RhemaScript capabilities/interfaces/specialists, and an integrated capstone.
- **Practice brief:** each unit states objectives, sources, task, prerequisites and a four-part rubric: accuracy, reasoning, execution and evidence.
- **Evidence verifier:** each assessment must be a canonical JSON artifact whose exact bytes are verified by the local evidence verifier. The assessment payload hash must match the verified evidence SHA-256.
- **Assessment binding:** the assessment ID, evidence ID, evidence version, digest and score are bound together.
- **Learning record:** the existing readiness registry stores the assessment report and exact verified evidence version. Its hash/checkpoint and backup facilities are reused; no second RAEI evidence ledger is introduced.
- **Progress planner:** the next unit is selected from recorded outcomes and prerequisites, not from UI order or a caller-supplied status string.

## Learning sequence

1. Engineering foundations and full-stack practice.
2. AI/ML, language-model, retrieval, agent, evaluation and model-governance practice.
3. Whole-Bible literacy across all 66 books, with exact translation/version provenance; HINOVBSI is used for direct Hindi Scripture quotations.
4. Bible-only ethics cases.
5. RhemaScript capability, interface and specialist mastery.
6. Integrated readiness capstone.

The sequence is enforced by prerequisites in the registry. The integrated capstone requires independently reviewed final-domain units.

## Assessment and status rules

- Scores are integers from 0 through 4 for accuracy, reasoning, execution and evidence.
- A minimum score of 3 on every criterion and no critical failure produces **PROVISIONAL_PASS**.
- Any criterion below 3 or any critical failure produces **NEEDS_REMEDIATION**.
- A provisional pass can unlock the next practice unit, but it is not mastery certification.
- The current API accepts RAEI self-assessment only. It cannot create **INDEPENDENTLY_REVIEWED** status. That status is reserved for a future authenticated human-review credential and separate authority integration.
- A self-assessment is not project approval, execution authorization, generation permission, upload permission or publishing permission.

## Continuous learning loop

- **Per task:** learn the relevant concept, implement, test, record evidence and assess.
- **On failure:** preserve the failed artifact, reproduce the failure, identify root cause, correct it, add a regression test, and create a new assessment attempt. Never overwrite the failed record.
- **Weekly:** complete one cross-domain practical challenge and review weak competencies.
- **Monthly:** review competency trends, stale knowledge, source versions and unresolved remediation.
- **After incidents or architecture changes:** add a new lesson/test and revalidate affected units.

## Evidence and tamper controls

Assessment artifacts use canonical JSON. The caller builds a versioned assessment payload, writes its canonical JSON bytes to the configured local evidence root, and verifies that file. The resulting EvidenceVersion is tied to its exact in-process identity; caller-constructed or copied objects are rejected. The readiness registry stores the exact evidence digest and report, rejects replay with changed content, supports verification and HMAC checkpoints, and can create a backup.

SQLite plus a local hash is not immutable storage. Retain HMAC checkpoints independently from the database and protect the secret key separately. The process-local capability check is an application-layer guard, not a defense against arbitrary hostile code executing inside the same Python process.

## What this system can and cannot learn

It can accumulate approved project knowledge, curriculum progress, practical code/test evidence, failure lessons and measured competency. It can improve its task selection and project-specific guidance.

It cannot silently retrain ChatGPT's base-model weights, learn while no execution environment is running, or autonomously grant itself authority. Any model-weight training would require a separate, explicitly approved training pipeline, data governance, compute and evaluation plan.


## Local operator workflow

The local CLI uses one owner-only SQLite registry and a configured evidence directory. Run it from the repository root after installing the project in the current Python environment:

```bash
python -m raei init --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3"
python -m raei status --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --evidence-root "$HOME/.local/share/rhemascript/raei/evidence"
python -m raei next --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --evidence-root "$HOME/.local/share/rhemascript/raei/evidence"
python -m raei brief --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --unit-id CS-FOUND --evidence-root "$HOME/.local/share/rhemascript/raei/evidence"
python -m raei verify --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --evidence-root "$HOME/.local/share/rhemascript/raei/evidence"
```

For knowledge intake or a self-assessment, first place the canonical JSON artifact inside the configured evidence root. The CLI verifies the exact file bytes before it records the item:

```bash
python -m raei record-knowledge --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --evidence-root "$HOME/.local/share/rhemascript/raei/evidence" --artifact-path knowledge-item.json
python -m raei knowledge-search --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --evidence-root "$HOME/.local/share/rhemascript/raei/evidence" --query "python packaging"
python -m raei record-attempt --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --evidence-root "$HOME/.local/share/rhemascript/raei/evidence" --artifact-path assessment.json
```

The database parent must already exist, be owner-controlled and private (POSIX mode 0700 or stricter); the database is created owner-only (0600). The CLI refuses symlinked paths and does not create a missing registry during read operations. Every read operation also re-hashes all retained evidence files against their recorded SHA-256 and size; missing or altered evidence blocks the read. Pending knowledge is excluded from default search. RAEI self-assessments can earn only PROVISIONAL_PASS or NEEDS_REMEDIATION; they cannot create independent-review or production-approval status.


## Versioned curriculum integration addendum — BWSF V1.0

The RAEI curriculum is extended to `RAEI-CURRICULUM-1.1` with eight evidence-required thematic units (`BWSF-01` through `BWSF-08`) covering Solomon's discernment, Bezalel's craftsmanship, wisdom in trials, Proverbs' pursuit of wisdom, testing claims, stewardship, Nehemiah's prayerful planning, and Scripture's teaching/corrective role.

These units follow the existing Bible-only ethics domain and precede RhemaScript capability mastery. The curriculum registry reports 154 units and remains `CURRICULUM_DEFINED_NOT_ASSESSED` until actual evidence-backed assessments are recorded. Historical `RAEI-CURRICULUM-1.0` assessment records remain readable for unchanged unit IDs; new attempts must use the current curriculum version. No existing assessment is upgraded or rewritten.


## Versioned activity-history integration addendum — 2026-11-13

The existing SQLite `ReadinessRunRegistry` now also persists the RAEI activity-event history in an append-only `activity_events` table in the same database. Readiness, knowledge and training records append a corresponding `READINESS_RUN_RECORDED` event in the same transaction. Field finding intake appends `FINDING_CAPTURED` events. Event IDs are idempotent only for identical content; changed replay is rejected.

Each event binds canonical payload bytes, payload SHA-256, sequence, predecessor hash and event hash. Registry verification checks chain continuity and readiness-record/event correspondence. HMAC checkpoint V2 covers readiness records and the complete event-chain head. Older readiness-only records are explicitly imported through `LEGACY_READINESS_RECORD_IMPORTED` events. Existing V1 checkpoints remain verifiable only when no activity events exist.

This extends the existing SQLite registry; it does not introduce a parallel JSON learning ledger. The earlier PR #38 JSON ledger remains a separate, draft, unmerged candidate and is not merged wholesale. The current event history is local persistence with independently retained HMAC checkpoints, not tamper-proof storage.
