# RAEI Local and Codex Operator Runbook V1.0

**Purpose:** Provide a repeatable, least-privilege workflow for a human operator and a repository-aware coding agent to resume RAEI work without relying on chat memory.  
**Authority:** This runbook does not grant merge, deployment, account, provider, spending or publishing authority.  
**Prerequisites:** A locally cloned RhemaScript repository, Git, Python version supported by `pyproject.toml`, and an owner-controlled working environment.

## 1. Read before acting

From the repository root, read in this order:

1. `AGENTS.md`
2. `docs/RAEI_ENGINEERING_CONSTITUTION_V1.md`
3. `docs/RAEI_ACTIVATION_AND_GOVERNANCE_V1.md`
4. `docs/RAEI_CONTINUITY_CHECKPOINT_AND_RECOVERY_REGISTER_V1.md`
5. The task-specific architecture, interface, security and evidence contracts.

If instructions conflict, stop and surface the conflict. Do not silently choose the less restrictive rule. The Human Director's reserved authority and the six RhemaScript project gates remain in force.

## 2. Read-only repository preflight

Run from the repository root:

```bash
git status --short --branch
git branch --show-current
git rev-parse HEAD
git remote -v
git fetch --all --prune
git status --short --branch
git log -5 --oneline --decorate
git branch -vv
```

Fetching updates remote-tracking references but does not change the working tree. Do not run `reset`, `clean`, `checkout -f`, `rebase`, `push --force` or destructive cleanup to make the tree appear clean.

Before editing, record:
- current branch and exact HEAD;
- target base branch and exact SHA;
- working-tree changes and their ownership;
- relevant open PR and review/check state;
- the acceptance criteria and files in scope.

If uncommitted changes exist, preserve them and determine their owner before proceeding. Do not stash, overwrite or discard them without permission.

## 3. Establish a bounded task

Write a short task statement containing:
- observed problem or approved requirement;
- evidence supporting it;
- expected behaviour and non-goals;
- files/modules likely affected;
- security and authority boundaries;
- positive, negative and regression acceptance tests;
- rollback or recovery considerations.

Inspect existing implementations and tests before adding a new module. Reuse the current SQLite readiness registry, evidence verifier and event history where applicable. Do not introduce a second ledger or parallel authority.

## 4. Local environment and validation

Use an existing project environment where possible. Install only declared project dependencies and do not add a dependency or external service without approval.

```bash
python --version
python -m pip install --disable-pip-version-check -e .
python ci/run_ci.py
```

The repository's GitHub Actions workflow currently runs `python ci/validate_if18_read_only.py --report-file if18-validation-report.json`. Use the same full validation entry point when reproducing CI locally; inspect the script before relying on its scope.

For RAEI's local learning registry, use only a private owner-controlled path. The registry parent must already exist and be private (POSIX 0700 or stricter); the database is owner-only (0600). Example:

```bash
mkdir -p "$HOME/.local/share/rhemascript/raei/evidence"
chmod 700 "$HOME/.local/share/rhemascript/raei"
chmod 700 "$HOME/.local/share/rhemascript/raei/evidence"
python -m raei init --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3"
python -m raei status --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --evidence-root "$HOME/.local/share/rhemascript/raei/evidence"
python -m raei verify --database "$HOME/.local/share/rhemascript/raei/learning.sqlite3" --evidence-root "$HOME/.local/share/rhemascript/raei/evidence"
```

Do not create a new registry if one already exists. Never put secrets, OAuth tokens, private keys, refresh tokens or session cookies in the evidence directory or test artifacts.

## 5. Implementation discipline

- Make one coherent, bounded change at a time.
- Preserve the original observation and evidence; create a new version for changed content.
- Use deterministic synthetic fixtures for tests. Label them synthetic.
- Add negative tests for invalid identity, wrong scope, stale evidence, replay, tampering, unauthorized transitions and failure paths where relevant.
- Never weaken an invariant or delete a failing test merely to make CI green.
- Review the complete diff for unintended changes and secrets.
- Do not claim a test ran unless its output or CI record is available.

## 6. Git and pull-request handling

Before committing:

```bash
git diff --check
git diff --stat
git diff
git status --short
```

Commit only files in the approved task scope. Push only to the explicitly designated feature branch when repository write access and task scope permit it. Never merge the PR or push to `main` as part of ordinary continuation.

After pushing:
1. Read the branch head from GitHub.
2. Confirm the PR base SHA and candidate SHA.
3. Inspect CI runs and require the exact current head SHA.
4. Record completed, failed, cancelled and pending runs honestly.
5. Re-read the PR state and compare ahead/behind values.

A green check on a previous commit does not validate a later commit. A mergeable PR is not merge approval. A successful synthetic workflow is not production certification.

## 7. Google and YouTube boundaries

The default work mode is offline and read-only. Google authorization is not needed for repository inspection, code review, local tests or synthetic fixtures.

If a task genuinely requires Google account authorization:
- first identify the exact read-only or write operation and why repository/local evidence is insufficient;
- state the minimum OAuth scopes and data required;
- inspect the current consent configuration and owner checklist;
- stop and request the owner's explicit decision before initiating authorization.

No OAuth scope expansion, live channel connection, upload, metadata/thumbnail edit, scheduling or publishing is permitted by this runbook. Publishing continues to require the separate existing approval gates and explicit owner authorization.

## 8. Stop and recovery

Stop immediately if:
- branch, base or exact HEAD is ambiguous;
- working-tree changes cannot be attributed;
- evidence bytes, digest or size mismatch;
- history/checkpoint verification fails;
- a required approval or identity policy is absent;
- CI is failing or does not correspond to the current SHA;
- a provider write result is indeterminate;
- the action would incur unapproved cost or cross an owner-only boundary.

Preserve the current state and evidence. Do not blindly retry external writes or automatically restore/overwrite a database. Compare with independently retained checkpoint material and request the minimum required owner decision.

## 9. Handover format

At the end of each work session, update the continuity register with:
- repository and date;
- main SHA, branch and exact HEAD;
- PR number/state/base/head/ahead/behind;
- exact-head CI run IDs and conclusions;
- changed paths and artifact hashes;
- commands/tests actually run;
- failures and their corrections;
- residual risks, blockers and owner actions;
- one next bounded task with acceptance criteria.

A new session must repeat the preflight. Do not trust a prior chat transcript as proof that the repository has not changed.

## 10. Explicit non-goals

This runbook does not authorize or perform merge, deployment, production identity integration, paid APIs, new subscriptions, Google OAuth expansion, YouTube writes, media generation, publishing or changes to protected BEZALEL/future-platform assets.

**End — RAEI Local and Codex Operator Runbook V1.0**
