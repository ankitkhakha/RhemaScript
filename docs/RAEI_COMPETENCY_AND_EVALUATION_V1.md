# RAEI Competency and Evaluation Standard V1.0

## Purpose and rules
Make capability observable and repeatable. Prefer unfamiliar task variants; require reasoning, assumptions and trade-offs; evaluate implementation and test evidence; include invalid, boundary, hostile-input and failure scenarios. Security and authority compliance are mandatory. Record assessment scope and environment. Reassess after remediation; never silently overwrite a failure.

## Rubric
Score applicable dimensions 0–4: fundamentals; independent reasoning; correctness; maintainability; testing/debugging; security/privacy; architecture/trade-offs; documentation/evidence integrity. Score meanings are defined in the Education Framework. Critical authority bypass, fabricated evidence, exposed secret or knowingly unsafe regression is automatic failure regardless of aggregate score.

## Challenge bank
1. **Fundamentals:** explain a concept and solve a changed example.
2. **Code comprehension:** explain an unfamiliar module's inputs, outputs, invariants, dependencies and error paths before editing.
3. **Algorithm design:** compare alternatives, discuss complexity and justify choice.
4. **Architecture/reuse:** identify the correct extension point and demonstrate no duplicate capability or authority.
5. **Debugging:** reproduce defect, find root cause, fix and add regression test.
6. **Security:** identify trust boundaries and abuse cases; test invalid input and denial; demonstrate safe failure.
7. **Refactoring:** improve maintainability while preserving behaviour through regression tests.
8. **Delivery:** produce traceable change, test receipts, limitations and rollback notes.

## Result states
NOT_ASSESSED; IN_PROGRESS; NEEDS_REMEDIATION; PROVISIONAL_PASS; INDEPENDENTLY_REVIEWED. These states describe evidence only and never grant permissions.

## Evidence record
Assessment ID/version; date; repository commit/source version; learning stage/objectives; task variant; permitted resources; environment and commands; result and test evidence; rubric scores and critical failures; reviewer role; remediation/reassessment links; limitations and next learning objective.

## Independence
The authoring agent cannot be the sole reviewer for high-risk security work or independent-assurance claims. A suitably qualified reviewer must be appointed and review evidence documented. This standard does not appoint a reviewer.

**End — RAEI Competency and Evaluation Standard V1.0**
