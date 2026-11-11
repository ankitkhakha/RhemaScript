# RhemaScript Project Readiness Report V1.0

**Module:** `rhemascript.reports`  
**Purpose:** Produce a read-only, human-readable structured summary from an existing orchestration result.

## Included sections

- Project and run identity.
- Capability assessment statuses and exact missing evidence/dependencies.
- Optional evidence gaps, separated from blockers.
- Existing six-gate status, findings and next required gate.
- Separate generation-authorisation presence and missing critical generation capabilities.
- Explicit action flags for generation, external actions and publishing.

## Interpretation rules

- `ASSESSED_FOR_HUMAN_REVIEW` is an assessment, never an approval.
- `NOT_ASSESSED` and `BLOCKED_DEPENDENCY` are blockers.
- `NOT_ASSESSED_OPTIONAL` is reported separately and is not promoted to a critical blocker.
- `generation_preconditions_met` reports only the orchestrator's precondition calculation. It is not an execution command or permission to act.
- Execution flags are copied from the orchestration result and remain false in the current orchestrator implementation.

This module is deterministic and read-only. It does not change evidence, gates, approvals, project status, audit records or execution state.
