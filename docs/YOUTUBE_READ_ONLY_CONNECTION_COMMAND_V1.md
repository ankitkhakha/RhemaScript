# Read-only YouTube connection command V1.0

**Status:** Merged into `main` in commit `2e5940618a18278899a69ed9ca7a548f35d33645`. Post-merge GitHub Actions synthetic CI passed in run [43146990690](https://github.com/ankitkhakha/RhemaScript/actions/runs/43146990690) on 2026-11-12. The owner reported that the read-only OAuth connection and expected channel-ID match completed on 12-Nov-2026; this workspace has not independently re-read the local credential or repeated the live check.

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
- The connection command's gateway is explicitly enabled only for this read-only operation. A successful read-only connection does not authorize publishing. Each project requires its Evidence Pack, six approved gates, final-film evidence, and externally issued V3 project/version/request-scoped approvals. Live provider writes remain separately gated and are not enabled by this command or by a general blanket approval.
- No upload, metadata mutation, thumbnail change, scheduling, or publication is enabled or authorized by a successful connection check.
- No credential values are to be pasted into ChatGPT, issue comments, source files, CI logs, or audit records.
- This command is a connection diagnostic, not deployment or OAuth consent setup. The owner reported that the read-only connection and expected channel-ID match were completed on 12-Nov-2026; the local credential is not stored in Git and was not independently re-read by this workspace. Re-run locally after credential rotation, account changes, token expiry or a refresh failure. The captured External/Testing consent configuration implies a seven-day refresh-token lifetime for the YouTube read-only scope; see the OAuth lifecycle addendum in YOUTUBE_GOOGLE_CONNECTION_READINESS_V1.md.

## Repeatable validation harness

From the repository root, run:

```bash
python ci/validate_if18_read_only.py --report-file if18-validation-report.json
```

The harness checks that the IF-18 binding contains exactly `OAUTH_TOKEN` and `CHANNEL_READ`, then runs the full contract and synthetic test suite through `ci/run_ci.py`. The JSON report contains the overall pass/fail result, check statuses, UTC generation time, and explicit limitations. It contains no credentials, access tokens, channel IDs, or channel titles.

The harness is synthetic-only: it does not load the operator's credential file and does not contact Google. A PASS is not a live channel-identity certification. CI uploads the redacted report as a short-retention workflow artifact when the workflow runs. The workflow runs on pull requests targeting `main` and pushes to `main`, `ci/**`, and `feat/**` branches.

## Validation

The added synthetic tests cover successful identity match, identity mismatch, missing credential file, timestamped audit output, secret/channel redaction, and the exact two-operation IF-18 allowlist. CI results must be inspected before treating the implementation as validated.


## Reauthorization diagnostics

The command safely distinguishes Google token-endpoint failures:
- `AUTHORIZATION_REQUIRED` / exit 3 for `invalid_grant`: the stored refresh token was rejected; verify the Desktop client configuration, then repeat the owner-operated read-only consent flow if the token is expired or revoked.
- `CLIENT_CONFIGURATION_ERROR` / exit 2 for `invalid_client`: verify the matching Desktop client ID and secret. Do not repeat consent as the first remedy.
- `OAUTH_CONFIGURATION_ERROR` / exit 2 for `invalid_scope`, `unauthorized_client` or `invalid_request`: correct the OAuth client or scope configuration.
- Other failures return generic `FAILED` and keep response details redacted.

For the captured External/Testing consent screen and `youtube.readonly` scope, Google documents seven-day refresh-token expiry. If the successful token was issued on 12-Nov-2026, plan to verify locally before approximately 19-Nov-2026. Do not create repeated refresh tokens unnecessarily; Google limits each Google Account to 100 refresh tokens per OAuth client ID.


## Resumable upload indeterminate-write recovery

The current candidate requires a durable `SQLitePublishSessionRegistry` and a separate owner-only AES-GCM session URL vault before an upload session or chunk can reach the provider. The registry binds project/version/request, approval fingerprint and exact final-film artifact identity; the bearer session URL is encrypted in the vault under a separately injected key, while the registry stores its digest. Resume verifies already-consumed V3 approvals as resume-only and checks the same artifact binding before retrieving the URL. A resumed operation never creates a replacement session.

The registry enforces monotonic acknowledged offsets and one in-flight operation. Bounded leases remain in force through session binding and 308 acknowledgement; a new gateway may claim an ACTIVE session only after the prior owner's lease expires, then it must query provider status before sending any further bytes. A live lease cannot be claimed by another gateway. If the provider reports an impossible range or an indeterminate outcome, the operation fails closed.

Two crash states remain explicit limitations. A crash while the session is still `CREATING`, before the URL is durably bound, is a manual-reconciliation state; the system must not automatically create another provider session. A crash after a 200/201 response is recorded as `COMPLETE` but before the completion audit/finalization may leave the caller without a recoverable provider resource ID/audit record. These are tracked recovery gaps, not authorization to retry. No exactly-once guarantee is claimed across all provider failures.

All current tests use synthetic registries and mocked transports. They do not contact Google, prove live provider behavior, validate production key custody or satisfy independent security review.
