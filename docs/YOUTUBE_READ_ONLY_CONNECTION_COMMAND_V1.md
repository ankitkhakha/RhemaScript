# Read-only YouTube connection command V1.0

**Implementation status:** The read-only connection command is merged into `main` in commit `2e5940618a18278899a69ed9ca7a548f35d33645`; its post-merge synthetic CI passed in run [43146990690](https://github.com/ankitkhakha/RhemaScript/actions/runs/43146990690). **Owner verification update (2026-11-12):** OAuth authorization and live IF-18 channel identity verification have since succeeded locally using the isolated bootstrap that was subsequently merged into `main` in commit `63b8d7285790e6237ddf87082965d550954f602b`. The expected channel matched. The current grant is `youtube.readonly` only. PR #40 is merged into `main`; no upload, thumbnail write, analytics query or publication was performed.

## Purpose

Provide one operator-facing command to load the existing owner-only credential file, authenticate through the official Google OAuth token endpoint, call the authenticated channel-read operation through IF-18, compare the returned channel ID with the owner's expected channel ID, and append a redacted audit trail.

## Command

Run from the repository root:

```bash
python -m rhemascript.integrations.connection \
  --credential-file /absolute/private/path/youtube-oauth.json \
  --expected-channel-id UC_EXPECTED_CHANNEL_ID \
  --audit-file /absolute/private/path/youtube-connection-audit.jsonl
```

The credential file's parent directory must be owner-only (0700 or stricter); the credential file must be a regular non-symlink file owned by the current user with 0600 permissions or stricter. The audit parent must also be an owner-controlled, non-symlink directory with 0700 permissions. The audit file is created/tightened to 0600.

## Exact operation boundary

The command constructs a dedicated IF-18 provider binding with exactly two operations:

- `OAUTH_TOKEN`: POST to Google's OAuth token endpoint to exchange the stored refresh token for a short-lived access token.
- `CHANNEL_READ`: GET the authenticated channel's snippet through YouTube Data API v3.

The binding contains no upload-session, upload-chunk, thumbnail-write, metadata-write, scheduling, or publishing operation. The command does not call `upload_video`, `set_thumbnail`, or any other write method. A write operation attempted through this command's gateway binding is rejected because no matching operation is configured.

## Identity and audit

A successful result requires exactly one authenticated channel and an exact match with the supplied expected channel ID. The console result redacts channel ID and title.

The existing JSONL audit sink records UTC timestamps, IF-18, provider, request correlation, operation, HTTP method, approved host, request fingerprint, byte counts/status where available, and phase. The final identity-check event uses a one-way SHA-256 fingerprint derived from the expected/returned identity values; it does not store either raw channel ID or channel title. OAuth secrets, access tokens, authorization headers, response payloads, query values, and refresh-token request bodies are not audit fields.

A mismatch or failed check is recorded as FAILED and the command exits non-zero. The audit directory must exist before invocation. Do not place the credential or audit file in a repository, shared folder, or source-control workspace.

## Security and governance boundary

- IF-18 is the only external provider interface used.
- Existing credential-file validation remains in force: POSIX owner-only permissions, regular file, no symlink, exact JSON key set, no overwrite behavior.
- The connection command's gateway is explicitly enabled only for this read-only operation. The owner has not authorized publishing through this read-only connection; it does not exercise or confer project-level publishing authority. Each project remains subject to its Evidence Pack, six approved gates, final-film evidence, human director acceptance, and explicit project-level publishing authorization.
- No upload, metadata mutation, thumbnail change, scheduling, or publication is enabled or authorized by a successful connection check.
- No credential values are to be pasted into ChatGPT, issue comments, source files, CI logs, or audit records.
- This command is a connection diagnostic, not deployment or publishing authorization. The owner has already completed the live read-only identity check locally; retain this procedure for repeat verification when needed. The OAuth bootstrap used for the successful owner run is now merged into `main` in commit `63b8d7285790e6237ddf87082965d550954f602b`.

## Repeatable validation harness

From the repository root, run:

```bash
python ci/validate_if18_read_only.py --report-file if18-validation-report.json
```

The harness checks that the IF-18 binding contains exactly `OAUTH_TOKEN` and `CHANNEL_READ`, then runs the full contract and synthetic test suite through `ci/run_ci.py`. The JSON report contains the overall pass/fail result, check statuses, UTC generation time, and explicit limitations. It contains no credentials, access tokens, channel IDs, or channel titles.

The harness is synthetic-only: it does not load the operator's credential file and does not contact Google. A PASS is not a live channel-identity certification. CI uploads the redacted report as a short-retention workflow artifact when the workflow runs. The workflow runs on pull requests targeting `main` and pushes to `main`, `ci/**`, and `feat/**` branches.

## Validation

The added synthetic tests cover successful identity match, identity mismatch, missing credential file, timestamped audit output, secret/channel redaction, and the exact two-operation IF-18 allowlist. CI results must be inspected before treating the implementation as validated.
