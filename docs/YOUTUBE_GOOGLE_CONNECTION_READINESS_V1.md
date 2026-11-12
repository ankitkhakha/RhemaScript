# RhemaScript YouTube — Google Connection Readiness V1

## Purpose and boundary

This is an owner-operated readiness checklist for connecting RhemaScript to an existing Google Cloud project and the intended YouTube channel. It does not perform OAuth, change Cloud settings, enable APIs, access the channel, grant publishing authority, or make an external request.

The integration is implemented against Google's official YouTube Data API v3 and YouTube Analytics API. A successful local preflight or CI run is not proof that Google has granted access. **Current status (2026-11-12):** the owner has completed OAuth and a live read-only IF-18 channel identity check; the intended channel matched. The granted scope is `youtube.readonly` only. PR #40 contains the isolated OAuth bootstrap but remains open/draft and is not merged into `main`. The setup and staged-activation instructions below remain the baseline for future operators; the completed read-only steps do not need to be repeated. Upload, thumbnail, analytics and publishing checks remain outstanding and require their own permissions and approvals.

## 1. Confirm the existing Google Cloud project

In Google Cloud Console, select the existing project intended for RhemaScript. Record its project ID in the owner's private operational notes only; it is not a credential and does not need to be placed in source control.

Before proceeding, the owner must verify:
- This is the intended project and account.
- The project's billing state and any organisation policy are understood.
- No billing account is enabled or changed as part of this procedure without separate owner approval.
- YouTube API quota is available and the applicable quota limits are understood.
- No paid resources, servers, databases, hosted services or subscriptions are being created.

YouTube API quota is quota-based and is not a promise of unlimited or universally available access. Do not interpret "no paid SDK or per-call API charge added by this repository" as a guarantee that every Google Cloud configuration is free of cost or restrictions.

## 2. Enable only the required official APIs

In the selected project, review and enable only:
- YouTube Data API v3
- YouTube Analytics API

Do not enable unrelated APIs for this integration. API enablement is a Google Cloud project change and must be performed by the project owner. This repository does not perform it.

## 3. Configure OAuth consent and the client

Create or review the OAuth consent configuration for the application and follow the current Google verification, audience and test-user requirements that apply to the owner's account and intended use.

Create an OAuth client suitable for a locally executed installed application (Desktop app), if supported for the chosen consent configuration. Keep the downloaded client configuration outside the repository and in a private local directory.

The owner must confirm:
- The consent screen identifies the intended RhemaScript application.
- The intended Google account is allowed to authorise it.
- The requested scopes are exactly the minimum needed for the selected operations.
- Any testing-mode restrictions, test-user requirements or verification requirements are understood.
- The OAuth client type is appropriate for a local installed application.

Do not place client secrets, refresh tokens, access tokens, downloaded OAuth client JSON, or private credential files in Git, GitHub issues/PRs, CI variables, shared drives, screenshots, terminal transcripts or ChatGPT.

## 4. Requested OAuth scopes

The current client operations are designed around these scopes:

| Scope | Intended use |
|---|---|
| \`https://www.googleapis.com/auth/youtube.upload\` | Upload videos |
| \`https://www.googleapis.com/auth/youtube.readonly\` | Read channel/video information |
| \`https://www.googleapis.com/auth/yt-analytics.readonly\` | Read YouTube Analytics reports |

Request only scopes needed for the features the owner intends to activate. If beginning with a read-only connection check, do not request upload permission merely for that check; use a separate least-privilege authorisation plan. A later upload capability requires the upload scope and the separate RhemaScript publishing authority.

Google may change scope classification, verification or consent requirements. The owner must review the current Google OAuth documentation and consent screen before granting access.

## 5. Obtain and protect the refresh token

The owner must obtain offline access through Google's supported OAuth flow for the intended channel account. Verify that the flow returns a refresh token and that the consented account is the intended channel owner or authorised channel manager.

### Recommended local file option (POSIX)

The client supports an optional owner-only local credential file. The repository provides an interactive setup helper for Linux/macOS:

1. Create a private directory outside the repository, for example `~/.config/rhemascript`, and set its permissions to `0700`.
2. Run:

~~~bash
python -m rhemascript.integrations.credentials --path "$HOME/.config/rhemascript/youtube-oauth.json"
~~~

3. Enter the OAuth client ID, client secret and refresh token at the prompts. Secret inputs are hidden.
4. Load credentials from the file:

~~~python
from rhemascript.integrations import YouTubeConfig
config = YouTubeConfig.from_private_file(
    "~/.config/rhemascript/youtube-oauth.json"
)
~~~

5. Run the offline preflight:

~~~bash
python -m rhemascript.integrations.preflight \
  --credential-file "$HOME/.config/rhemascript/youtube-oauth.json" \
  --audit-log "$HOME/.config/rhemascript/youtube-audit.jsonl"
~~~

The helper creates a new file with mode `0600`, refuses to overwrite an existing file, requires an existing owner-only parent directory (`0700` or stricter), and never prints credential values. The loader checks file type, symlink status, size and permissions.

**Important:** this file is plaintext protected by filesystem permissions, not encrypted and not an OS keychain. Protect local account access and backups. Keep it outside Git, synchronised folders and shared drives. The built-in helper refuses non-POSIX platforms because equivalent ACL protections cannot be verified here. On Windows or other unsupported platforms, use the operating system's credential manager and inject the variables through a protected process-launch mechanism.

### Environment-variable alternative

The current client also supports:
- `RHEMASCRIPT_YOUTUBE_CLIENT_ID`
- `RHEMASCRIPT_YOUTUBE_CLIENT_SECRET`
- `RHEMASCRIPT_YOUTUBE_REFRESH_TOKEN`

Environment variables are not an encrypted vault. Avoid shell history, command-line arguments, shared process listings, broadly readable shell startup files, logs and crash reports. Never send the values to ChatGPT or paste them into GitHub.

## 6. Prepare the local audit destination

Choose an existing local directory controlled by the operator. It should not be a repository, synchronised/shared folder, public web root, CI workspace or temporary directory. On POSIX systems, the preflight rejects a group/world-writable parent and an existing audit file with permissions broader than owner-only.

The audit file is created only when the gateway is actually used. The offline preflight does not create it. Protect and back it up according to the project's retention policy. The JSONL sink is a local append-only audit record, not tamper-proof remote archival.

## 7. Run the offline preflight

After configuring the local environment and audit path, run:

\`\`\`bash
python -m rhemascript.integrations.preflight --audit-log "/absolute/path/in-an-existing-private-directory/youtube-audit.jsonl"
\`\`\`

This checks local credential presence without displaying values, and checks the audit destination. It does not validate credentials, contact Google, inspect Cloud settings, verify channel identity, or enable the gateway.

A failed check is a stop condition. Correct the local configuration and rerun. Do not bypass the preflight by weakening file permissions or writing secrets into source control.

## 8. Staged activation sequence

The recommended order is:

1. **Local readiness:** complete Sections 1–7. No network call.
2. **Read-only OAuth validation:** only after the owner explicitly authorises a live connection check. Confirm the authenticated channel identity and record a redacted audit event. Do not upload, change thumbnails or modify channel settings.
3. **Permission review:** owner confirms channel identity, OAuth scopes, API access, quota and audit location.
4. **Publishing readiness:** separately validate the project's approved Evidence Pack, all six approved gates, exact approved final-film evidence, Human Director acceptance and explicit PUBLISH authority.
5. **Private test upload:** only after a separate explicit authorisation for a specific approved test asset. Verify the returned video ID, processing and private privacy state.
6. **Public or scheduled release:** requires a separate human decision and publishing authorisation for the specific project/video and release timing.

No stage implicitly authorises the next. A successful read-only connection does not authorise upload. A private test upload does not authorise public release.

## 9. Current implementation status

Implemented in PR #28:
- Standard-library OAuth refresh and YouTube API client.
- IF-18 provider binding through the existing external gateway.
- Fail-closed gateway routing, host/path/method restrictions and request auditing.
- Local JSONL audit sink.
- Offline local preflight for environment variables or the protected credential file.
- Interactive POSIX local credential-file setup and permission-checked loading (plaintext, owner-only file; not encrypted storage).
- Mocked tests for channel reads, resumable upload, video verification, thumbnail write, authority checks and audit redaction.

Not yet performed or verified:
- Google Cloud project selection, API enablement, billing/quota review or consent configuration.
- OAuth consent or refresh-token acquisition.
- Live authenticated channel identity check.
- Live analytics query.
- Live upload or thumbnail write.
- Public or scheduled publication.
- Deployment, merge or production activation.

## 10. Stop conditions

Stop and request owner review if:
- The project, billing state, API quota or consent requirements are unclear.
- Google requests a billing change or paid resource.
- The OAuth account is not the intended channel owner/manager.
- The granted scopes exceed the approved operation.
- A refresh token cannot be protected locally.
- The audit destination is shared, public, symlinked or writable by other users.
- The live response differs from the documented API contract.
- Any Evidence Pack, gate, final-film approval, human acceptance or publishing authority check fails.

Never solve a stop condition by logging secrets, bypassing the gateway, disabling audit, skipping project gates or weakening publishing authority.
