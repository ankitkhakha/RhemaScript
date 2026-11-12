# IF-18 owner verification checklist V1.0

**Status:** Merged into `main`; owner-run local verification remains pending. The owner has approved enabling publishing capability in RhemaScript. This approval does not authorize ChatGPT, CI, or any other remote process to access the owner's Google account.

## Objective

Verify that the existing local YouTube OAuth credential file authenticates the intended channel through IF-18 using only the `OAUTH_TOKEN` and `CHANNEL_READ` operations. This is a read-only identity check, not publishing authorization.

## Before running

- [ ] Confirm the owner intentionally wants to perform a live read-only connection check. PR #28 is merged; synthetic CI passing is not a substitute for live verification.
- [ ] Use the existing credential file already prepared by the owner. Do not paste, upload, email, or commit it.
- [ ] Confirm the credential file is a regular file owned by the current OS user, is not a symbolic link, and has permissions `0600` or stricter.
- [ ] Confirm its parent directory is owner-only (`0700` or stricter).
- [ ] Identify the intended YouTube channel ID locally from a trusted owner-controlled source. Do not paste it into ChatGPT, a PR comment, or a shared log.
- [ ] Choose an audit output path outside the repository and any shared/synchronized folder. Its parent directory must already exist, be owner-controlled, non-symlink, and have permissions `0700` or stricter.
- [ ] Ensure the audit output path does not point into source control.

## Run the read-only check

From the RhemaScript repository root, replace the three placeholders locally:

```bash
python -m rhemascript.integrations.connection \
  --credential-file /absolute/private/path/youtube-oauth.json \
  --expected-channel-id UC_EXPECTED_CHANNEL_ID \
  --audit-file /absolute/private/path/youtube-connection-audit.jsonl
```

The command exchanges the refresh token at Google's OAuth token endpoint and reads the authenticated channel through YouTube Data API v3. The IF-18 gateway binding for this command allows exactly:

- `OAUTH_TOKEN`
- `CHANNEL_READ`

It does not enable video upload, metadata changes, thumbnail writes, scheduling, or publishing.

## Acceptance criteria

- [ ] The process exits successfully.
- [ ] The result indicates the authenticated channel identity matched the locally supplied expected channel ID. The console intentionally redacts channel ID and title.
- [ ] A new audit event is present in the owner-only JSONL audit file.
- [ ] The final identity event is marked successful and contains only the one-way identity fingerprint, not the raw channel ID or title.
- [ ] No access token, refresh token, authorization header, credential body, or raw channel identity appears in the audit file or shared logs.
- [ ] No video, thumbnail, metadata, schedule, or publication change was made.

## Stop conditions

Stop and do not retry with altered permissions or a different channel ID if any of the following occurs:

- The credential file or audit path fails its ownership, permission, regular-file, or symlink checks.
- Authentication fails, the channel lookup fails, more than one channel is returned, or the identity does not match.
- The command exits non-zero or the audit record is missing/incomplete.
- Any unexpected write or publishing behavior is observed.

Keep the full audit file and diagnostic output private. If assistance is needed, share only a manually reviewed, sanitized error summary; never share credentials, tokens, channel IDs, channel titles, or unredacted audit data.

## What a successful check proves

A successful local run proves that the supplied credential file authenticated and that the returned channel matched the expected channel ID at the time of the check, using the read-only IF-18 command boundary.

It does **not** prove publishing readiness, establish the actual channel connection, grant new Google permissions, or satisfy any project-level publishing gate. CI runs are synthetic-only and do not contact Google.

## Governance sign-off

- Owner-run live verification: pending until the owner executes the command locally.
- PR #28 review and merge: completed; merge commit `2e5940618a18278899a69ed9ca7a548f35d33645`.
- Publishing capability approval: granted by the owner. Actual publishing remains blocked for each project until its Evidence Pack, six approved gates, final-film evidence, human director acceptance, and explicit project-level publishing authorization are all present.
