# RhemaScript Project Evidence Pack & Run Manifest V1.0

**Status:** Initial validated implementation  
**Module:** `rhemascript.evidence`  
**Authority:** Evidence organisation only. Existing capability contracts, six project gates and separate approval, execution, final-acceptance and publishing authorities remain unchanged.

## Purpose

A project evidence pack is a version-bound index of source material, approved creative artefacts, capability evidence, provenance links and existing gate records. It supplies structured evidence to the existing Creative Production Orchestrator. It is not a new approval system, media store or execution command.

## Manifest contents

- `manifest_id` and `schema_version`.
- Validated `project_record`; project ID and version are binding keys.
- `artifacts`: stable artifact ID, type, project/version binding, artifact version, status and optional evidence references.
- `evidence_records`: stable evidence ID, existing CAP ID, payload, evidence references and artifact references.
- `source_to_final_links`: source artifact ID, target artifact ID and relationship.
- Optional existing `gate_records`, passed to the current six-gate validator unchanged.

Evidence payloads for the same CAP are merged only when repeated keys have identical values. Conflicts fail closed. The pack compiles capability evidence for the orchestrator.

## Integrity controls

- Unique artifact and evidence IDs.
- Exact project ID/version binding for every artifact.
- All artifact references resolve.
- Provenance links resolve, cannot self-reference and form a directed acyclic graph.
- Script and narration artefacts labelled as approved require an explicit APPROVED, VERIFIED or ACCEPTED status; approval is never inferred from the type name.
- If an EDITED_FILM exists, the full ordered chain must exist and be connected: biblical source → approved script → approved narration → storyboard → audio-visual plan → prompt → asset → edited film.
- Partial packs are valid before an edited film exists; the orchestrator reports capability evidence gaps.

## Run behaviour

`validate_evidence_pack` validates and normalises the pack. `run_evidence_pack` validates first, then sends compiled evidence and existing gate records to `CreativeProductionOrchestrator`. The pack does not bypass capability, dependency or gate checks. Generation, external actions and publishing remain unperformed.

## Limits

References are caller-supplied identifiers; remote files are not fetched or verified. No binary media storage, durable database, signature service, retention engine or immutable audit store is added. Human approval authenticity still depends on the existing gate-record process and review. No frame or waveform inspection is implemented.


## Canonical schema and starter template

- JSON Schema: `schemas/project-evidence-pack-v1.schema.json` (Draft 2020-12).
- Starter manifest: `templates/project-evidence-pack-v1.template.json`.
- The starter is a valid empty DRAFT project manifest and passes the runtime evidence-pack validator.
- Replace sample project identifiers and add version-bound artefacts/evidence as the project progresses.
- The JSON Schema describes the manifest structure; the Python runtime validator remains authoritative for cross-record checks such as project/version binding, reference resolution, provenance acyclicity and complete source-to-final linkage.
- Do not place generation authorisation in the manifest. Existing gate records are supplied as records; the separate execution-authorisation input remains outside the evidence pack.
