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
