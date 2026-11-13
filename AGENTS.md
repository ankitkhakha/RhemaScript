# Repository Agent Instructions

These instructions apply to all work in this repository. They are operating boundaries, not a grant of authority.

## 1. Source of truth and session start

- Read the applicable project documentation before changing code, especially the RAEI Engineering Constitution, RAEI Activation and Governance Guide, RAEI Field Intelligence Engine, and the RAEI Continuity, Priority and Recovery Register.
- Inspect the live Git state before acting: repository, current branch, clean/dirty state, exact HEAD, target base SHA, open PR state and exact-head CI.
- Never rely on a previous chat summary as proof of current repository state.
- Preserve existing approved work. Do not reset, clean, rebase, force-push, amend shared history, delete branches or discard uncommitted work unless the Human Director explicitly authorizes that exact action.

## 2. Scope and approvals

- Work only on the explicitly selected task and branch. Prefer one bounded change with explicit acceptance criteria.
- RAEI activation or a general "continue" instruction does not authorize merging, deployment, production configuration, external writes, Google OAuth scope expansion, YouTube uploads/edits/publishing, spending or paid services.
- Preserve all six existing RhemaScript project approval gates and the separation between technical review, approval, execution authorization, final acceptance and publishing authorization.
- Do not change authority masters, approval policy, trusted identity policy, signing keys or protected BEZALEL/future-platform assets without separate explicit approval.
- Never infer a real human identity, approval, provider connection or production capability from synthetic fixtures or passing tests.

## 3. Evidence and integrity

- Distinguish observed, implemented, tested, proposed, synthetic, owner-action-required and unknown states.
- Bind claims to exact artifact ID/version/path/SHA-256/byte length and exact source commit or CI run when applicable.
- Verify bytes locally before trusting a digest; do not trust caller-supplied verification flags or filenames.
- Do not fabricate evidence, test output, CI status, timestamps, approvals, identities or completion.
- Retain failed test/CI history and describe corrections honestly.
- Treat a hash chain as tamper-evident, not immutable against an attacker who can rewrite all records and anchors. Verify independently retained checkpoint material.
- Never make a stale assessment appear current after its source evidence or implementation changes.

## 4. Secure engineering

- Never print, commit, copy into fixtures, or place in reports any passwords, OAuth tokens, refresh tokens, private keys, signing secrets, session cookies or personal data not needed for the task.
- Use least privilege and offline/synthetic tests by default. Do not connect a production identity provider, directory, KMS/HSM, Google account or YouTube channel without the specific owner approval and approved scope.
- Fail closed on missing, ambiguous, stale, mismatched or indeterminate authorization/evidence.
- Never blindly retry a provider write whose outcome is indeterminate. First reconcile the provider state using the approved read-only path.
- Do not weaken tests, remove negative cases, broaden trusted roles or change security defaults merely to make CI pass.
- Review dependencies and workflow changes for supply-chain and secret-exposure risk. Do not add paid services or external dependencies without approval.

## 5. Implementation and validation

- State the task, acceptance criteria, intended files and prohibited actions before implementation.
- Make the smallest coherent change. Avoid unrelated refactors and parallel writes to the same file or branch.
- Run the narrowest relevant tests, then the full project CI command when feasible; report commands and actual outcomes.
- Inspect the exact resulting diff, check for accidental secrets, and verify changed artifact bytes and hashes.
- Re-read the live branch head and PR metadata after writes. CI only validates the exact commit SHA it ran against.
- If CI is pending, absent, cancelled or attached to another SHA, report it as not yet validated.
- Do not merge or deploy. Leave candidate PRs draft/open unless the Human Director separately authorizes the exact merge action.

## 6. Stop conditions

Stop without further writes if branch/base/head is ambiguous, evidence verification fails, history integrity fails, authorization is missing, a security boundary would be crossed, CI reveals an unresolved failure, or the task exceeds approved scope. Preserve the observed state and report the blocker and the minimum owner decision required.

## 7. Session handover

At the end of each meaningful work session, update the RAEI continuity register with:
- date/time and repository;
- main SHA, working branch and exact head;
- PR state and ahead/behind counts;
- exact-head CI run IDs and conclusions;
- changed files and artifact hashes;
- tests actually run and failures/corrections;
- outstanding risks, owner actions and prohibited operations;
- one next bounded task and its acceptance criteria.

Do not state that a stop/resume test passed unless a fresh session actually performed it using the recorded checkpoint.

## 8. Cost and external systems

The operating constraint is ₹0 additional monthly spend. Use existing tools and offline/synthetic tests where practical. No paid API, infrastructure, subscription, external integration, deployment or account connection may be introduced without separate explicit approval.
