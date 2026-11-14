# RhemaScript Repository Governance and Branch Protection V1.0

**Status:** Required administration runbook; configuration is not applied by this document.
**Target:** `main` branch and PR #62 (`feat/ieif-raei-integration`).
**Authority:** Repository protection only. This does not approve, merge, deploy or change application approval gates.

## 1. Required protection for main

Apply a GitHub branch ruleset (preferred) or classic branch protection rule matching exactly `main`:

- Require a pull request before merging.
- Require at least two approving reviews from distinct eligible reviewers.
- Dismiss stale approvals when new commits are pushed.
- Require approval of the most recent reviewable push by someone other than its pusher.
- Require Code Owner review for files covered by `CODEOWNERS`; create and independently validate that file before enabling this requirement.
- Require all review conversations to be resolved.
- Require the exact status check context `Full contract and synthetic integration CI`.
- Require the branch to be up to date before merging, after confirming the CI workflow is deterministic and completes within the repository's operational limits.
- Block force pushes and branch deletion.
- Apply the rules to administrators and repository owners; leave the bypass list empty except for a documented emergency break-glass identity with independent audit.
- Do not allow merge commits if the repository adopts a linear-history policy; choose and document squash or rebase merge consistently.

## 2. Pull request acceptance gates

A PR may leave Draft only after:
1. all exact-head required checks pass;
2. two independent reviews are approved and current for the latest head;
3. all review threads are resolved;
4. the complete changed-file review and security findings are recorded;
5. required identity, key custody, audit and recovery operations are independently verified for the actions being enabled;
6. the six existing RhemaScript project approval gates remain intact.

PR #62 must remain Draft until the independent review and operational blockers are closed. Passing CI is not a substitute for reviewer approval.

## 3. Evidence and verification

Record the ruleset ID, target pattern, enforcement status, required status-check context, required reviewer count, bypass actors, administrator enforcement and audit timestamp. Verify the effective rule against `main` after saving; do not rely only on a successful settings-page submission.

The connected GitHub integration in this session can read repository rulesets, but its branch-protection API request returned HTTP 403 (administration permission unavailable). The rulesets collection was readable and returned an empty list at the latest inspection. A prior read-only inspection reported classic branch protection disabled; current classic protection could not be re-read because of the permission boundary. No protection settings were changed.

## 4. Administrator action required

A repository administrator must apply the above policy in GitHub repository Settings → Rules → Rulesets (or Settings → Branches for classic protection), then independently verify the effective policy and provide the resulting ruleset/protection evidence. Do not claim this gate complete until that evidence is available.
