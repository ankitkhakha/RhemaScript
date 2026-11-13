# RAEI Continuity, Priority and Recovery Register V1.0

**Status:** Controlled operating register; documentation baseline on PR #62 feature branch.  
**Recorded:** 13 November 2026.  
**Repository:** `ankitkhakha/RhemaScript`.  
**Scope:** RAEI engineering continuity and evidence-governed execution. This register does not grant repository, production, account, provider or publishing authority.

## 1. Purpose and governing principles

This register prevents loss of decisions, evidence, implementation state and authority boundaries between work sessions. It is subordinate to the RhemaScript Engineering Constitution, RAEI governance, project approval gates and the Human Director's authority.

The required work cycle is:

1. Idea and observation.
2. Research and learning.
3. Knowledge-gap analysis.
4. Evidence acquisition or explicit evidence-design.
5. Verification and independent review.
6. Findings and confidence/limitations.
7. Decision and explicit approval.
8. Planning with exact approved scope.
9. Controlled implementation.
10. Independent outcome/effectiveness assessment.
11. Governed closure, reopening where justified, and evidence-preserving learning.

Do not collapse these stages. A plan is not implementation authority; implementation is not proof of effectiveness; CI success is not production certification; a technical approval is not Google authorization or permission to publish.

## 2. Verified continuity checkpoint — 13 November 2026

The following state was read from GitHub during this checkpoint:

| Item | Verified state |
|---|---|
| Repository | `ankitkhakha/RhemaScript` |
| Default branch | `main` |
| Main commit | `c44d8e9c0847bd220167945b967db74fcf12635f` |
| Principal integration PR | #62 — authenticated IEIF–RAEI governance and YouTube approvals |
| PR #62 head at checkpoint | `1e267ccb9138fdab5f22f80ebcf496c64c1487c9` |
| PR #62 base | `main` at the commit above |
| PR state | Open, draft, unmerged |
| Compare at checkpoint | 441 commits ahead, 0 behind |
| Exact-head CI | Runs #1561 and #1562 succeeded on the checkpoint head |
| Deployment / live writes | Not performed |

The exact-head CI result applies to `1e267ccb9138fdab5f22f80ebcf496c64c1487c9`, not to any later commit. A documentation or code change creates a new head and must receive its own validation before it is described as validated.

Older open drafts based on previous mainline commits must not be merged wholesale or treated as current. Reconcile each change against the current main and PR #62 before considering integration. Preserve their history and evidence; do not delete branches or close drafts as a shortcut.

## 3. Current capability and evidence distinctions

The PR #62 candidate records implementation and exact-head CI for authenticated finding research, independent reproduction, governed disposition, planning, implementation, independent effectiveness assessment, governed closure, closed-finding knowledge inheritance and controlled reopening/new-version resumption.

The inherited knowledge record begins as pending review and unverified; inheritance does not certify truth, source authenticity or relevance.

Use these evidence labels consistently:

- **Observed:** directly read from a live repository, tool result or supplied artifact.
- **Implemented:** code or documentation exists at a specific commit; this alone does not imply runtime deployment.
- **Tested:** a named test or CI run completed on an exact commit.
- **Proposed:** design or acceptance criteria exist but implementation is not established.
- **Synthetic:** test fixtures or simulated adapters; never represent them as real-world identity, provider or production evidence.
- **Owner action required:** requires a human-controlled account, credential, policy, approval or operational decision.
- **Unknown / not verified:** evidence is absent or was not checked. Do not infer success.

Every assessment must identify the exact evidence ID/version, artifact path, SHA-256 and byte length where applicable. Bind results to the precise source commit and test run. Retain failed runs and explain their correction; never rewrite a failure as a pass.

## 4. Priority backlog and acceptance rules

Work in this order unless new evidence or a Human Director decision changes priority:

### P0 — Continuity and safe resumption
- Keep this register current at each meaningful checkpoint.
- Record branch, base, exact head, PR state, latest exact-head CI, changed artifacts and outstanding owner decisions.
- Preserve prior approved work and never overwrite a checkpoint with an unverified status.
- Acceptance: another operator can resume from this register without guessing or repeating already verified work.

### P1 — Evidence and history assurance
- Verify evidence artifact existence, exact bytes, SHA-256 and byte length.
- Bind assessments and decisions to immutable evidence versions and source commits.
- Verify append-only history, event IDs, hash-chain continuity and independently retained checkpoint anchors.
- Add adversarial tests for forged verification, artifact substitution, rewritten/truncated history, replay and stale assessments.
- Acceptance: each negative test demonstrates rejection without an unauthorized state transition or history append.

### P2 — Integration and dependency assurance
- Revalidate the combined candidate against the current main commit.
- Review dependency and supply-chain exposure, secrets boundaries, key custody, identity-policy configuration, failure modes and provider idempotency.
- Distinguish synthetic adapter conformance from real provider/identity integration.
- Acceptance: exact-head CI passes, security findings are dispositioned, and unresolved operational dependencies are explicitly recorded.

### P3 — Operational interfaces and controlled handover
- Review local operator/Codex instructions for least privilege, evidence capture, branch discipline and stop conditions.
- Test stop/resume from a clean session using this register.
- Document owner-side steps for Google authorization only when a specific read-only or write operation genuinely requires it.
- Acceptance: the operator can identify what is executable now, what requires owner action and what remains prohibited.

### P4 — Production readiness (separately approved)
- Production identity provider and authoritative directory.
- Owner-approved role and authentication assurance policy.
- Issuer service, signing-key custody/HSM/KMS, revocation and independent audit operations.
- Production environment, monitoring, recovery and independent security review.
- Any deployment, Google authorization expansion, provider write, upload, thumbnail change or publishing.
- Acceptance: explicit owner approval for each relevant boundary, operational evidence and a separate production-readiness decision. Passing CI alone never satisfies this gate.

## 5. Checkpoint and recovery protocol

At the start of a resumed session:

1. Read the current `main` ref and all relevant open PR metadata from GitHub.
2. Read the candidate branch head and confirm its base SHA.
3. Fetch exact-head workflow runs; report only completed results for that exact SHA.
4. Compare candidate with current main; inspect ahead/behind and changed files.
5. Read this register and the governing documents from the candidate commit.
6. Check for new commits, review comments, failing checks, changed approvals or revoked authority.
7. Select one bounded next task and state its acceptance criteria before editing.

Before a change:

- Record the starting branch and exact head.
- Preserve the prior head and all evidence.
- Avoid parallel writes to the same branch or file.
- Never force-push, rewrite history, merge, deploy or alter protected authority masters as a recovery shortcut.
- Do not store secrets, tokens, private keys or credential material in repository files, logs or this register.

After a change:

- Record the resulting commit SHA and changed paths.
- Verify artifact content and hashes where relevant.
- Wait for and inspect CI on the exact resulting head.
- Re-read branch/PR metadata and confirm no unexpected movement.
- Update this register only with observed facts; clearly label any pending CI or owner action.

Recovery is not automatic restoration. If the branch, database, checkpoint or evidence differs unexpectedly, stop writes, preserve the observed state, compare against independently retained evidence and request the required owner decision. Never overwrite a newer or ambiguous state.

## 6. Stop conditions

Stop immediately and report the exact blocker if any of these occurs:

- Current branch, base or head cannot be established.
- Evidence bytes, digest, byte length or source version do not match.
- History verification fails, a replay is detected or a checkpoint anchor is unavailable.
- CI is failing, pending, absent or belongs to a different commit.
- A required identity, role, approval, policy or credential is missing or ambiguous.
- A provider write outcome is indeterminate; do not blindly retry.
- The requested action would exceed the approved scope, expose secrets, incur unapproved cost or cross an owner-only boundary.
- A proposed action would merge, deploy, publish, upload, modify a live channel or change protected BEZALEL assets without explicit separate authorization.

## 7. Zero-cost and authority constraints

The operating target remains ₹0 additional monthly spend. Prefer existing repository tooling and deterministic local/synthetic tests. Do not introduce paid APIs, paid infrastructure, external integrations or subscriptions without a separate explicit decision.

RAEI activation and a general instruction to continue do not authorize:
- merging any pull request;
- deploying or enabling production services;
- connecting a production identity provider or expanding Google OAuth scopes;
- YouTube uploads, edits, thumbnail changes or publishing;
- generating or spending on external services;
- changing the six existing RhemaScript approval gates or approval authority;
- modifying or deleting BEZALEL protected/future-platform assets.

## 8. Stop/resume acceptance test

A continuity handover is accepted only when a fresh session can, without relying on conversational guesswork:

1. identify the repository, main SHA, candidate branch, PR and exact head;
2. distinguish the last passed CI head from any newer unvalidated head;
3. identify the next bounded task, its acceptance criteria and dependencies;
4. list owner-only actions and explicit prohibitions;
5. verify that no merge, deployment, Google authorization expansion or live YouTube write occurred;
6. resume without discarding prior work or silently changing authority.

Record the test result as PASS, FAIL or NOT RUN with the exact checkpoint and evidence. Do not claim this test has passed merely because this protocol is documented.

## 9. Change control

This register is versioned. Amendments must preserve prior checkpoint facts, include the reason for change, identify the authorizing decision where one is required, and be validated on the resulting exact commit. Historical checkpoint entries are not silently rewritten.

**End — RAEI Continuity, Priority and Recovery Register V1.0**


## 10. Follow-on engineering checkpoint — 13 November 2026

**Repository state observed after the evidence-byte consistency hardening:**

- Main/base SHA: `c44d8e9c0847bd220167945b967db74fcf12635f`.
- Feature branch: `feat/ieif-raei-integration`.
- Candidate SHA: `afd91860b14846fbcf23e9ebf5a9df0852181b33`.
- PR #62 remains open and draft; no merge or deployment occurred.
- Candidate is 449 commits ahead and 0 behind the recorded base at this checkpoint.
- Exact-head CI run #1576 succeeded on the candidate SHA: `https://github.com/ankitkhakha/RhemaScript/actions/runs/43396638166`.
- Earlier runs #1574 and #1575 succeeded on the immediately preceding code candidate `42277ad500834e88b786daa07bfd007da72a01e0`; they are not substitutes for #1576.

### Evidence-consumption correction

The RAEI CLI previously hashed a JSON evidence file and then reopened it to obtain its identity or payload. The new `verify_json_artifact` path reads through descriptor-relative, no-follow file descriptors, derives the evidence ID/version from that byte snapshot, hashes those same bytes, and returns those exact immutable bytes to the caller. The CLI now parses and processes the returned bytes without reopening the evidence path.

Added negative/positive coverage for valid JSON identity, malformed/non-object JSON, symlink rejection, exact digest/size, and ensuring a later on-disk replacement does not change the already verified byte snapshot.

### Process-restart coverage

The RAEI CLI test harness now invokes each command in a separate Python interpreter using `python -m raei`. Existing init/status/next, knowledge, training, finding and tamper-read tests therefore exercise persisted registry recovery across process boundaries rather than only calling the CLI entry point in one interpreter.

This is automated process-restart coverage, not a claim that a human operator has completed the full clean-session handover exercise.

### Residual boundaries

- The main `ReadinessRunRegistry` remains the durable lifecycle/event-history store; its hash chain and external HMAC checkpoint are tamper-evident only when the checkpoint is retained independently.
- The standalone `AssessmentRegistry` is not the authoritative lifecycle history and must not be treated as independently tamper-proof.
- CI remains synthetic/offline; no live Google authorization, YouTube channel verification, publishing, deployment or production identity integration has been performed.
- PR #62 remains unmerged and draft. Passing CI is not merge approval or production certification.

### Next bounded task

Continue the dependency/security review and inspect every assessment and evidence persistence path for consistency with the authoritative readiness/event registry. Resolve or explicitly disposition the standalone assessment registry's integrity boundary before treating P1 evidence/history assurance as closed.


## 11. Assessment persistence and dependency reproducibility review — 13 November 2026

### AssessmentRegistry disposition

Repository-tree inspection at candidate `781bd27d6fc7357ee98f4d1c7c91a95ea8f00426` found `AssessmentRegistry` referenced only by its implementation module and its dedicated unit tests. No application/runtime module imports it.

Its `verify()` method compares table columns with a duplicate JSON representation stored in the same SQLite database. This can detect accidental mismatch, but a party able to rewrite the database can rewrite both representations consistently. It has no independently retained checkpoint or external trust anchor. Therefore it cannot establish authenticity or detect a coordinated database rewrite.

**Disposition:** explicitly classify this class as an experimental local helper, not an authoritative lifecycle ledger. Do not route production RAEI decisions, governed assessments, approvals or closure through it. The authoritative history remains `ReadinessRunRegistry` activity events, with independently retained HMAC checkpoints. No second ledger is being introduced. Reconsider integration only through a separately scoped design and adversarial review.

### Dependency reproducibility

At this checkpoint:

- `pyproject.toml` declares Python `>=3.11` and `cryptography>=42.0.0,<48.0.0`.
- CI executes Python 3.12.
- The repository tree contains no `uv.lock`, `poetry.lock`, `Pipfile.lock`, hash-locked requirements file or constraints file.
- CI installs the project using `pip install -e .`, so the cryptography version and transitive dependency resolution are not locked to exact hashes.

**Finding:** CI success demonstrates the resolved dependency set used by that run, not reproducible dependency resolution across future runs. Do not invent a lock or pin an unobserved version. Next action is to capture the exact resolved versions from a successful CI run, select a lock-generation approach compatible with the repository's zero-cost/manual-first constraints, then test a clean install from the resulting lock before claiming reproducibility.

### CI workflow hardening status

The CI workflow now pins the three external GitHub Actions to immutable commit SHAs, disables persisted checkout credentials, limits repository permissions to read-only contents, and pins the runner image to Ubuntu 24.04. Exact-head CI #1580 passed on `781bd27d6fc7357ee98f4d1c7c91a95ea8f00426`.

This does not lock Python package dependencies and does not constitute production security certification.

## 12. Exact-head CI evidence and observed dependency resolution — 13 November 2026

### Repository and pull-request state

- Candidate branch: `feat/ieif-raei-integration`.
- Exact candidate SHA: `940ca85ef6dc209e23cdad35dc223a4a427eef5c`.
- Main/base SHA: `c44d8e9c0847bd220167945b967db74fcf12635f`.
- Compare result: 453 commits ahead, 0 behind.
- PR #62: open, draft, unmerged; GitHub reports mergeable and clean at this observation.
- No merge, deployment, live Google authorization or YouTube write was performed.

### Exact-head CI run #1583

- Run: `43398267178`.
- Job: `131794446565`, “Full contract and synthetic integration CI”.
- Run head SHA exactly matches the candidate SHA above.
- Run conclusion: success. Setup, checkout, Python setup, dependency installation, full local CI suite and report upload all completed successfully.
- Python runtime observed: CPython `3.12.16`.
- Exact dependency versions resolved in this run:
  - `cryptography==47.0.0`
  - `cffi==2.1.1`
  - `pycparser==3.12`
  - local editable project `rhemascript-new-system==0.1.0`
- These versions are an observed snapshot from this CI run only. They are not a dependency lock, do not establish artifact hashes for every dependency, and do not guarantee future resolver output.

### Retained IF-18 report

The workflow uploaded artifact `if18-read-only-validation-report` (artifact ID `14023079856`, 659-byte ZIP; 14-day retention configured).

The archived JSON report was downloaded and inspected. Its SHA-256 is:

`a7b11a7e5130fe1c99ac925ed32663772a1325ff328ff7a0952ab3140d43e7c6`

The report records:
- overall status `PASS`;
- full contract and synthetic test suite exit code 0;
- IF-18 allowlist limited to `CHANNEL_READ` and `OAUTH_TOKEN`;
- no publishing operations in the allowlist;
- `publishing_enabled=false`;
- `live_google_connection_attempted=false`;
- validation mode `SYNTHETIC_ONLY`.

The report explicitly states that it does not prove live OAuth consent, account access or channel identity, and that the channel owner must run the separate read-only connection command locally. The report is evidence of the CI validation mode and result, not proof of live account connectivity.

### Dependency reproducibility disposition

The previously missing observation of resolved package versions is now captured above. The dependency reproducibility issue remains open: the repository still declares version ranges and installs with `pip install -e .`; no hash-locked dependency manifest has been introduced or tested. Do not convert this single-run snapshot into pins without a deliberate lock-generation and clean-install validation task.

### Remaining boundary

This exact-head pass validates the repository's local contracts and synthetic tests. It does not close P1 evidence/history assurance, complete the clean-session human handover test, provide production identity/key custody, establish live YouTube authorization, or authorize merge, deployment or publishing.

## 13. Validation of the continuity-register update — 13 November 2026

The section 12 update was committed as `4c3f6902ef6389db85ed8dc2062ba13f4a06c1b4`. Both workflows completed successfully on that exact SHA:

- Push CI run #1584: `43398537906` — success.
- Pull-request CI run #1585: `43398545339` — success.
- In both runs, dependency installation, the full local CI suite and IF-18 report upload succeeded.

The IF-18 artifact from run #1583 was downloaded and its JSON inspected independently. The JSON file is 889 bytes and has SHA-256 `a7b11a7e5130fe1c99ac925ed32663772a1325ff328ff7a0952ab3140d43e7c6`. It records synthetic-only validation, read-only IF-18 operations, publishing disabled and no live Google connection attempt.

At this observation, PR #62 remains open and draft, its head is `4c3f6902ef6389db85ed8dc2062ba13f4a06c1b4`, GitHub reports mergeable/clean, and the compare against main SHA `c44d8e9c0847bd220167945b967db74fcf12635f` is 454 commits ahead and 0 behind. This is a point-in-time repository state; recheck before any future integration decision.

The next bounded work remains dependency reproducibility and adversarial review of evidence/history persistence. No lockfile has been invented, and no production or owner-only action has been performed.

## 14. Direct-read integrity guard — 13 November 2026

### Finding and bounded correction

A code review found that `ReadinessRunRegistry.get(run_id)` returned a single readiness record without first verifying the registry. Unlike `list_all()` and `list_activity_events()`, this direct-read path could return a payload whose stored digest or canonical representation had been altered, without surfacing the registry-integrity failure.

The method now calls `verify()` before reading and raises an integrity error when the registry is invalid. A regression test modifies a stored readiness payload without updating its digest and confirms that `get()` fails closed.

### Exact candidate and validation

- Implementation commit: `e12860f26fe6f6269213d33d8af6ff9ba8bb37f9`.
- Regression-test commit / candidate head: `5a0530483fe2462b297788b09e3a654e7d544188`.
- Exact-head PR CI run #1590: `43402096229` — success; dependency installation, full local CI suite and IF-18 report upload all passed.
- Push-triggered run `43402090159` for the same head was still pending at this checkpoint; the successful PR-triggered run is the observed exact-head validation.
- The correction does not change the checkpoint key model, provide independent checkpoint custody, or establish production readiness.

PR #62 remains open and draft. At this checkpoint the candidate compares 457 commits ahead and 0 behind the recorded main SHA. No merge, deployment, Google authorization or live YouTube write occurred.


## Atomic read-snapshot hardening — 13 November 2026

A concurrency review found that integrity verification and checkpoint construction read related SQLite tables in separate autocommit SELECTs. Under WAL, a valid writer can commit between those reads, causing a mixed-time view (for example, readiness rows from before a commit and its event row from after it). This is a consistency defect, not evidence that an attacker can forge a valid HMAC.

The readiness registry now holds one explicit read transaction while it reads readiness rows, activity events and append-only trigger metadata for `verify()`, and while it reads both tables for checkpoint snapshot digests. The approval-consumption store likewise holds one explicit read transaction across consumed and revoked approval tables when constructing checkpoint bytes. SQLite WAL readers retain a stable snapshot while concurrent writers commit; this behavior is documented by SQLite: https://www.sqlite.org/isolation.html.

Adversarial interleaving tests arrange a real second-connection commit after the first table has been read. They assert that the in-flight verification/checkpoint snapshot remains internally consistent and that the concurrent commit is visible to a subsequent read. This does not replace independent HMAC checkpoint custody, and it does not make local SQLite storage tamper-proof.


## Readiness registry local-storage permissions — 13 November 2026

A storage-boundary review found that the readiness registry rejected a symlink at the database path but did not enforce private ownership and permissions on the database file or its parent directory. The registry now fails closed unless it runs on POSIX, the database parent is a real owner-owned directory with mode 0700 or stricter, and the database is an owner-owned regular file with mode 0600 or stricter. New databases are created exclusively with no-follow semantics and owner-only permissions. These checks are repeated at each connection. Symlinked ancestor directories are rejected.

Existing legacy databases remain migratable only when their existing file and parent permissions already meet the private-storage policy; migration does not silently relax permissions. Operators must secure the containing directory before opening the registry. This is an intentional security requirement and may require correcting deployment paths before upgrading.

Adversarial tests cover default owner-only creation, group/world-readable database rejection, public parent rejection, symlinked database rejection and symlinked ancestor rejection. Exact code/test head `a9efb1220720e6c3b85610a0e675be6f9f096608` passed the complete contract and synthetic integration suite in GitHub Actions run #1716: https://github.com/ankitkhakha/RhemaScript/actions/runs/43420044583.

POSIX permission checks protect against other local users; they do not defend against a malicious process running as the same owner, compromised administrator, or attacker able to rewrite both the database and independent checkpoint/key custody. External checkpoint retention and separate key custody remain required.
