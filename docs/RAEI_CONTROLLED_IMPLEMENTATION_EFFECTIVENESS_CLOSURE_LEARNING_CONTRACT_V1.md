# RAEI Controlled Implementation, Effectiveness, Closure & Learning Contract V1.0

**Status:** Candidate implementation transition is implemented and synthetic integration CI passed on `5a34e7110d04f7693f50a6d559120e491d27698a` (run #1446). Effectiveness is now implemented in the candidate and passed exact-head CI run #1458 on `0771e284a751abebedaf657b9bacf170eddfe10d`. Two-person governed closure is implemented and passed CI run #1482. Closed-finding knowledge inheritance is now implemented and passed exact-head CI run #1498 on `d3d854d0ec7dd2a7471526de6f973bf513e54909`. Reopening remains proposed.
**Authority:** A recorded plan is not permission to execute it. The Human Director retains existing decision and execution authority. No new approval gate is silently activated by this document.
**Scope:** Candidate-only design for the remaining RAEI finding lifecycle. This document does not authorize live project changes, production deployment, provider writes, media generation, upload or publishing.

## 1. Lifecycle and non-equivalence

The intended version-bound sequence is:

1. Capture — preserve the original observation and exact source evidence.
2. Research — authenticate the research report and bind exact evidence bytes.
3. Reproduction — independently authenticate the reproduction result.
4. Governed disposition — two distinct approvals decide whether the finding is accepted, rejected, duplicate, deferred or withdrawn.
5. Planning — authenticate a plan only after the prior research, REPRODUCED result and ACCEPTED disposition gates.
6. Implementation — separately authorize and record the actual bounded change against the exact plan.
7. Effectiveness — an independent assessor evaluates outcomes against the exact plan and implementation.
8. Closure / learning — governed closure records the outcome and transfers verified learning without rewriting the original finding or evidence history.

A plan, an implementation record, a test result, an effectiveness assessment and a closure decision are different claims. None may be inferred from another.

## 2. Implementation transition contract

**Candidate implementation status:** `record_finding_implementation` and the registry's transactional `FINDING_IMPLEMENTED` event are implemented. The report binds the exact prior plan event and plan evidence tuple; the registry enforces consumed V3 approval, project/version scope, identity-domain consistency, independent implementer separation and replay protection. The finding projection validates and exposes `IMPLEMENTED`. Synthetic tests cover the successful transition and planner-identity reuse rejection. CI run #1446 passed on the exact implementation/test head above.

Proposed action: `FINDING_IMPLEMENT`.

Required preconditions:
- Exact captured finding ID and version exist.
- Exactly one accepted plan exists for that finding version.
- The implementation report identifies the exact plan event ID and exact plan evidence tuple: evidence ID, evidence version, SHA-256 and byte length.
- The implementation report itself is independently byte-verified and bound to the V3 approval.
- The V3 approval is consumed, unexpired, project/version/request scoped, and carries the configured identity claims.
- Implementer subject and session differ from the submitter, researcher, reproducer and planner, where those authenticated identities are present; provider and immutable policy version remain consistent.
- The event ID is deterministic for the finding/version/request. Exact idempotent replay may return the existing result; changed replay must fail.
- The implementation record contains actual changes, exact source revisions, test commands/results, deviations and rollback reference. Planned tasks must not be represented as completed changes.
- The registry must re-check prior event order and exact plan evidence in the same transaction that appends the event.

The report template is `templates/raei-finding-implementation.template.json`. Placeholder hashes and IDs must be replaced with verified values. A filled template is not itself proof that implementation occurred.

## 3. Effectiveness assessment contract

Proposed action: `FINDING_EFFECTIVENESS_ASSESS`.

Required preconditions:
- Exactly one authenticated implementation event exists for the same finding version.
- The assessment binds both the implementation event ID and its exact evidence tuple.
- The effectiveness report itself is byte-verified and bound to the V3 approval.
- Assessor subject and session differ from the submitter, researcher, reproducer, planner and implementer where those identities are known; identity provider and immutable policy version match the trusted domain.
- Assessment evaluates every approved acceptance criterion against observed results, defined measurement window, environment and limitations.
- Outcomes are strictly `EFFECTIVE`, `INEFFECTIVE` or `INCONCLUSIVE`. Missing evidence cannot be silently converted into success.
- One terminal assessment per finding version; changed replay, stale approval, altered report or substituted implementation evidence is rejected.

The report template is `templates/raei-finding-effectiveness.template.json`. It is a proposed evidence shape, not an implemented API or an assessment result.

**Candidate effectiveness status:** `record_finding_effectiveness` and transactional `FINDING_EFFECTIVENESS_ASSESSED` are implemented. They require the exact prior implementation event/evidence tuple, a consumed V3 approval, an independent assessor, and a supported outcome (`EFFECTIVE`, `INEFFECTIVE`, `INCONCLUSIVE`). The finding projection exposes the exact outcome. Synthetic tests cover effective assessment and rejection of implementer reuse. CI run #1458 passed on the exact head above.

## 4. Closure and re-opening contract

Closure is a separately governed transition, not a side effect of implementation or a passing test.

- `EFFECTIVE`: eligible for a closure review after all criteria, residual risks and evidence lineage are checked.
- `INEFFECTIVE`: must remain open or return to a newly versioned research/planning cycle; cannot be marked resolved.
- `INCONCLUSIVE`: remains open pending additional evidence or an explicitly governed decision to stop investigating. It must not be presented as effective.
- Closure review must bind the exact finding version, accepted disposition, plan, implementation and effectiveness event IDs and evidence tuples.
- Closure approvals must be distinct authenticated subjects and sessions, use permitted action roles, and be consumed atomically.
- Closure is append-only. Re-opening creates a new lifecycle event referencing the prior closure; it never edits or deletes history.
- Any change to the original observation, plan, implementation or evidence creates a new version or superseding record. Old assessments do not automatically carry forward.

**Candidate closure status:** `record_finding_closure` and governed `FINDING_CLOSED` are implemented. Closure requires an EFFECTIVE assessment, exact plan/implementation/effectiveness event lineage, the exact assessment evidence tuple, and two consumed V3 approvals bound to that evidence. Reviewers must have distinct subjects and sessions, be independent of all lifecycle participants, and share one trusted identity-provider/policy domain. Projection validates the lineage and exposes `CLOSED`. Synthetic tests cover successful closure and rejection of INEFFECTIVE outcomes. CI run #1482 passed on the exact head above.

## 5. Knowledge inheritance contract

A learning item may be proposed from a closed finding only when its source lineage is explicit.

Each proposed knowledge record must preserve:
- originating finding ID/version;
- research, reproduction, disposition, plan, implementation, effectiveness and closure event IDs where applicable;
- exact evidence IDs/versions/SHA-256/byte lengths;
- scope and conditions under which the lesson is valid;
- confidence, limitations, known counterexamples and review date;
- whether the lesson is observed, independently reproduced, authoritative, inferred or proposed.

Knowledge review is a distinct governed approval. A knowledge item must not be promoted to universal RhemaScript policy merely because one project outcome was effective. Reuse requires applicability review against the target project/version and its own approval gates.

## 6. Projection and integrity requirements

The finding projection must validate the full ordered event chain and all stored authorization/evidence envelopes before showing a later status. It must not rely only on the last event.

Expected display states include:
- `SUBMITTED`, `RESEARCHED`, `REPRODUCED`, `ACCEPTED`, `PLANNED`,
- `IMPLEMENTED`, `EFFECTIVE`, `INEFFECTIVE`, `INCONCLUSIVE`,
- `CLOSED`, `REOPENED`.

A disposition remains a separate governed event; projection precedence must not hide its rationale or evidence when a later stage exists. Every event must bind its previous stage's exact event ID and artifact tuple. The registry must reject out-of-order, duplicate, cross-version, cross-project, mismatched-evidence and self-approved transitions.

## 7. Required adversarial validation

Before claiming these stages implemented, tests must cover:
- missing plan, rejected/deferred disposition, non-REPRODUCED reproduction, wrong plan event ID and plan artifact replacement;
- approval for a different artifact, wrong project/version/request/action, expired or replayed approval;
- same subject, shared session, provider mismatch, policy-version mismatch and role escalation;
- evidence ID/version/hash/size mismatch and byte substitution after verification;
- duplicate event IDs with changed payload, reordered events, altered authorization claims, event-chain rewrite/truncation and stale projection;
- implementation report that claims planned tasks without change evidence;
- effectiveness report that omits criteria, misstates outcome or references a different implementation;
- attempted closure for INEFFECTIVE/INCONCLUSIVE outcomes, missing dual approval, replayed closure and improper re-open;
- knowledge item detached from source lineage, unsupported generalization, altered inherited evidence and unauthorized policy promotion.

Each test must assert both rejection and absence of an appended lifecycle event. Run the full contract/synthetic integration suite against the exact final candidate head after code changes.

## 8. Current boundary and next engineering increment

The candidate currently has authenticated research, independent reproduction, governed two-approval disposition and authenticated planning. The two new JSON templates and this contract are documentation/evidence-shape artifacts only. No implementation/effectiveness/closure/learning transition API is claimed by this change.

Governed reopening and new-version resumption are implemented and passed exact-head CI run #1522 on `441c5a645288b298ef343d931d52a765b73fb663`. Two consumed V3 approvals bind the exact previous closure evidence; reviewers must be distinct and independent from the prior closure reviewers. The reopening event identifies a proposed next version. `capture_finding` accepts a superseding version only when it matches that reopening event, references exactly the prior closed version, is numerically greater, and carries a distinct authenticated submitter. Historical closure remains append-only; projection marks the old version `REOPENED` and the new version `SUBMITTED`. Each new version must repeat research, independent reproduction, governed disposition, planning, implementation and assessment. Keep PR #62 draft/unmerged. Do not select or connect a production IdP, external directory, HSM/KMS, staging or production environment without owner approval.
