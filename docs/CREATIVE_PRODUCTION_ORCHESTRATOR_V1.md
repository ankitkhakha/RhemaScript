# RhemaScript Creative Production Orchestrator V1.0

**Status:** Initial implementation merged; dependency coordinator is evidence-bound and human-governed  
**Module:** `rhemascript.orchestration.creative_production`  
**Primary class:** `CreativeProductionOrchestrator`  
**Authority:** Existing CAP-01..CAP-15 contracts, six project approval gates, and separate approval/execution/final-acceptance/publishing authorities remain unchanged.

## 1. Purpose

The orchestrator coordinates existing capability specialists into one ordered project assessment. It is a coordinator, not a new domain authority and not an autonomous production agent.

It receives:
- a validated project record;
- evidence keyed by existing capability ID;
- an actor role;
- optional recorded human gate decisions;
- the separate generation-authorisation flag;
- an optional run identifier.

It returns:
- per-capability assessment status;
- exact missing evidence;
- blocked dependency reasons;
- phase-level status;
- six-gate progression status;
- project/version/run-linked audit trace;
- whether generation preconditions are satisfied.

## 2. Dependency model

| Capability | Depends on | Purpose in the sequence |
|---|---|---|
| CAP-01 | — | Source identity and provenance |
| CAP-02 | CAP-01 | Biblical interpretation risk review |
| CAP-03 | CAP-01, CAP-02 | Scripture-to-script integrity |
| CAP-04 | CAP-01 | Content opportunity and eligibility |
| CAP-05 | CAP-02, CAP-03, CAP-04 | Narration-led creative development |
| CAP-06 | — | Optional audience-learning evidence |
| CAP-07 | CAP-05 | Visual reference and continuity assessment |
| CAP-08 | CAP-05, CAP-07, CAP-09, CAP-10, CAP-12, CAP-13 | Production feasibility |
| CAP-09 | CAP-12 | Tool/model operation preflight |
| CAP-10 | CAP-13 | Asset intelligence with rights/provenance context |
| CAP-11 | CAP-08, CAP-10, CAP-13 | Final QC evidence |
| CAP-12 | — | Security and trust assessment |
| CAP-13 | — | Rights and provenance evidence |
| CAP-14 | — | Optional incident/failure triage |
| CAP-15 | CAP-11 | Optional version-linked performance learning |

The explicit topological order is maintained in `CAPABILITY_ORDER`; dependency relationships are maintained in `DEPENDENCIES`. Changes to either must be accompanied by tests proving that every dependency appears before its dependent capability and that no cycle is introduced.

## 3. Status semantics

- `ASSESSED_FOR_HUMAN_REVIEW`: required evidence was supplied and the existing capability handler ran. This does not mean the specialist found no issues and does not mean a human approved the result.
- `NOT_ASSESSED`: required evidence for this capability is missing. The exact missing keys are returned.
- `BLOCKED_DEPENDENCY`: one or more required upstream capabilities were not assessed because their evidence is missing or an earlier dependency was blocked.
- `NOT_ASSESSED_OPTIONAL`: optional learning/incident evidence was not supplied; this does not block the core production sequence.
- Phase status aggregates the capability states and is not an approval.

A capability result may contain findings requiring human attention even when its evidence was structurally sufficient to run the specialist. The orchestrator does not convert specialist findings into theological, creative, legal or security decisions.

## 4. Six approval gates

The orchestrator imports the existing `REQUIRED_GATES` and `ProjectGateState`. It validates supplied gate records in their existing order and checks project identity, actor identity and evidence references.

The six gates remain:
1. Project creative direction
2. Script biblical accuracy
3. Visual development
4. Production plan and prompt
5. Generation authorisation
6. Final film

The orchestrator does not create approvals, approve a gate, waive a gate, or change gate order. A capability assessment is never a gate approval.

## 5. Separate execution authority

Generation preconditions are considered satisfied only when:
- all six existing gates have approved records for the same project; and
- the separate explicit generation-authorisation flag is true.

Even then, this orchestrator performs no generation. It returns `generation_action_performed = false`. External actions and publishing are also always reported as not performed. A future execution adapter must independently enforce the existing authority controls and must not treat this assessment output as an execution command.

## 6. Traceability

Each audit row links:
- run ID;
- project ID;
- project version;
- capability ID;
- assessment status;
- supplied evidence references;
- actor role.

The caller should provide stable `evidence_refs` in each capability evidence object. The orchestrator preserves these references; it does not invent asset IDs, source citations, timestamps or approvals.

## 7. Current limitations and blockers

| Work | Current state | What is needed |
|---|---|---|
| Capability sequencing | Implemented | Maintain dependency tests as contracts evolve |
| Exact missing dependency reporting | Implemented | Keep evidence requirements current |
| Gate sequence validation | Implemented | Human gate records remain required |
| Actual image/video frame analysis | Not implemented | Verified analyser and frame-level evidence |
| Actual audio waveform analysis | Not implemented | Verified audio analyser and waveform/timing evidence |
| Live provider calls or media generation | Not implemented by this coordinator | Separate approved execution adapter, current provider contract and explicit execution authorisation |
| Durable audit persistence | Not implemented here | Approved persistence layer and retention controls |
| Publishing | Not implemented | Separate publishing authority and approved interface |

## 8. Safety boundary

This module does not:
- fetch Scripture or web sources;
- generate or edit images, video or audio;
- inspect a Google account, model entitlement or live interface;
- call external providers;
- write to external systems;
- spend credits or money;
- publish content;
- grant or infer human approval;
- claim production readiness or independent assurance.

It coordinates evidence already supplied to the existing capability layer. Human review and the existing source-to-final integrity chain remain mandatory.
