# RhemaScript YouTube Integration — zero-cost implementation

## Scope

This integration uses only Python's standard library and Google's official YouTube Data API v3 and YouTube Analytics API. It adds no package dependency, paid API, hosted service, or database. It does not create a Google Cloud project, enable an API, request OAuth consent, or store credentials.

Implemented client operations:
- Read the authenticated channel profile.
- Resumable video upload with title, description, tags, category, privacy and optional scheduled publication metadata.
- Thumbnail writes are deliberately disabled until a dedicated signed thumbnail-artifact approval contract is implemented.
- Verify upload/video processing and privacy status.
- Read channel analytics by date range, with optional video filter.

The client is dormant until explicitly instantiated with credentials. No network call occurs on import. Uploads and thumbnail writes fail closed unless the caller supplies a complete RhemaScript Evidence Pack. The client validates that pack with the existing evidence-pack validator, including project/version binding and the connected Source-to-Final chain; it then checks that the final-film artifact is approved, all six ordered gate records are approved, and the final gate references that exact final-film evidence. Explicit Human Director final acceptance and separate publishing authorisation are also required. The integration does not create or infer approvals. Uploaded videos default to `private`.

## Zero-cost setup boundary

YouTube API quota is not a per-call monetary fee, but it is limited and subject to Google's policies and quota allocation. This code does not promise that a particular Google account or Cloud project has API access or quota. The account owner must:
1. Use an existing Google Cloud project (do not create a paid resource).
2. Enable YouTube Data API v3 and YouTube Analytics API.
3. Configure an OAuth consent screen and an OAuth client for a local installed application.
4. Obtain offline OAuth consent for the RhemaScript YouTube channel with these scopes:
   - `https://www.googleapis.com/auth/youtube.upload`
   - `https://www.googleapis.com/auth/youtube.readonly`
   - `https://www.googleapis.com/auth/yt-analytics.readonly`
5. Supply the OAuth client ID, client secret and refresh token as local environment variables. Never commit them to Git.

Environment variables:
- `RHEMASCRIPT_YOUTUBE_CLIENT_ID`
- `RHEMASCRIPT_YOUTUBE_CLIENT_SECRET`
- `RHEMASCRIPT_YOUTUBE_REFRESH_TOKEN`

The refresh token must be obtained through Google's OAuth flow by the channel owner. This repository does not automate consent or capture account credentials. Access-token HTTP 401 responses trigger one refresh-and-retry attempt; other failures are not blindly retried. API responses are bounded to 8 MB, with oversized responses rejected.

## Minimal use

```python
from rhemascript.integrations import JsonlAuditSink, YouTubeClient, YouTubeConfig
from rhemascript.integrations.youtube import youtube_provider_binding
from rhemascript.interfaces.external import ExternalIntegrationGateway, UrllibTransport

# Choose an existing owner-controlled local directory with restricted access.
audit_sink = JsonlAuditSink("/secure/local/path/rhemascript-youtube-audit.jsonl")
# This example intentionally does not enable the gateway or perform OAuth.
gateway = ExternalIntegrationGateway(
    bindings=(youtube_provider_binding(),),
    transport=UrllibTransport(),
    credential_resolver=lambda provider: {},
    audit_sink=audit_sink,
    enabled=False,  # remain disabled until the owner explicitly enables it
)
client = YouTubeClient(YouTubeConfig.from_environment(), gateway=gateway)
# Only after owner-controlled configuration and authorization:
# channel = client.channel()

# Keep private unless the human director explicitly authorises publication.
# Supply the validated project Evidence Pack, including its six gate records
# and connected Source-to-Final artifact chain.
uploaded = client.upload_video(
    "approved-final.mp4",
    title="Approved title",
    description="Approved description",
    evidence_pack=approved_project_evidence_pack,
    final_film_evidence_ref="EVIDENCE-REF-FOR-FINAL-FILM",
    evidence_root="/absolute/path/to/verified/evidence",
    approval_verifier=production_approval_verifier,
    approval_credentials=(
        externally_issued_final_acceptance_credential,
        externally_issued_publish_credential,
    ),
    approval_request_id="owner-issued-request-id",
    tags=["RhemaScript", "Bible"],
    privacy_status="private",
)
verified = client.verify_video(uploaded["video_id"])
```

For a scheduled public release, YouTube requires the upload to be private and a valid future RFC3339 `publish_at` value. The client enforces private privacy when `publish_at` is supplied.

## Remaining external activation and assurance

The repository and its CI evidence do not establish that a live owner-operated OAuth connection or channel-identity check has been completed. Treat live authorization and channel identity as unverified until the account owner completes and records the separate read-only check below. Upload-scope and Analytics-scope consent, live upload, thumbnail write, public/scheduled release and Analytics access remain unperformed. API write permissions, quota and account-specific restrictions still require separate owner-led checks.

The existing interface gateway and project approval system remain intact. Do not add credentials to source control, CI variables, issue comments or pull requests. Before production use, add a local encrypted secret store if the deployment environment provides one; this implementation intentionally reads secrets from environment variables only.

## External gateway integration status

The YouTube client is now routed through the existing provider-neutral external gateway when an IF-18 gateway is explicitly supplied. The provider binding declares the supported Google hosts, API path families, and HTTP methods for OAuth, channel/video reads, analytics, resumable upload sessions, upload chunks, and thumbnail writes. The client refuses live traffic if neither an explicitly configured gateway nor an injected offline test transport is supplied. The direct `transport` injection is a test seam only; it is now blocked from dispatching mutating YouTube resource requests (apart from the exact OAuth token-exchange POST required by read-only tests). Production traffic must use the IF-18 gateway and its audit, allowlist and authorization controls.

### Read-only channel identity verification

After owner-led OAuth configuration, the first live validation should be a read-only identity check. Obtain the intended channel ID from the owner's own YouTube/Studio account records, then explicitly call:

~~~python
from rhemascript.integrations import YouTubeClient, YouTubeConfig
from rhemascript.integrations.youtube import youtube_provider_binding
from rhemascript.interfaces.external import ExternalIntegrationGateway, UrllibTransport

# Configure the existing IF-18 gateway and protected local audit sink first.
# Keep the gateway disabled until the owner separately authorises this test.
gateway = ExternalIntegrationGateway(
    bindings=(youtube_provider_binding(),),
    transport=UrllibTransport(),
    credential_resolver=local_credential_resolver,
    audit_sink=local_audit_sink,
    enabled=True,  # only for this separately authorised read-only check
)
client = YouTubeClient(YouTubeConfig.from_environment(), gateway=gateway)
identity = client.verify_connection(expected_channel_id="OWNER_CONFIRMED_CHANNEL_ID")
~~~

`verify_connection` requires an exact expected channel ID, refreshes OAuth if needed, calls only the authenticated channel-list read operation through IF-18, and fails if Google returns zero/multiple channels or a different channel ID. Its result contains only the matched channel ID, channel title (if supplied), and read-only/authenticated flags. It does not upload, change channel settings, set a thumbnail, run Analytics, or grant publishing authority.

For this check, configure only the read-only YouTube scope needed for channel identity (`youtube.readonly`). Do not request `youtube.upload` or `yt-analytics.readonly` until those separate features are explicitly being prepared. Google may impose additional consent/verification requirements; review the current Google requirements before consent. Do not copy the placeholder channel ID, credentials or token values into the repository.


The gateway extension preserves the original JSON POST invoke contract and adds a separate method-aware request path for OAuth and resumable protocols. Each provider request is audited without recording query values, authorization headers, OAuth body contents, upload-session URLs, or media bytes. Upload-session and upload-chunk operations are checked against the separate PUBLISH authority at the gateway boundary. Thumbnail writes are rejected by the client and gateway until a dedicated signed thumbnail-artifact approval contract is implemented. The YouTube client independently validates the Evidence Pack, all six ordered gates, final-film evidence, and human final acceptance before any publishing write.

Automated CI covers IF-18 gateway routing and fail-closed behavior and mocked resumable upload flows. Thumbnail write tests verify rejection before provider transport; they do not demonstrate a working thumbnail-write capability. A path-segment boundary hardening test also verifies that sibling paths outside an operation's declared prefix are rejected before transport. These are mocked contract tests, not live Google account or provider validation.

`JsonlAuditSink` is the included standard-library local audit sink. It appends JSON Lines metadata, accepts only a strict allowlist of audit fields, rejects payload/header/credential fields, creates or tightens the log file to owner-only permissions (0600), rejects symlink destinations where the platform supports `O_NOFOLLOW`, and calls `fsync` before returning. Its parent directory must already exist and be controlled by the operator. This is a local append-only log, not tamper-proof remote archival; protect and back up the containing directory according to the project's retention policy. Do not set enabled=True until the owner has reviewed the provider binding, selected and protected the audit-log location, configured the OAuth environment, and explicitly chosen to enable external requests. The read-only OAuth consent and channel identity check remain pending an explicit owner-run authorization and verification step. CI and local preflight do not perform this step. No upload-scope or Analytics-scope consent, live upload, thumbnail change, analytics query, public release, merge or deployment has been performed. A passing CI run validates mocked contracts only; it does not validate write permissions, quota, billing status or real write behavior.


### Local audit sink

The included `JsonlAuditSink` is exported from `rhemascript.integrations`. Example:

```python
from rhemascript.integrations import JsonlAuditSink

audit_sink = JsonlAuditSink("/absolute/path/in-an-existing-private-directory/youtube-audit.jsonl")
```

The sink does not create parent directories. Keep the log on a local filesystem with appropriate access controls; do not put it in a shared repository, public web root, or CI artifact. Each record is synchronously flushed and fsynced. The event schema excludes request bodies, headers, OAuth values, query values, resumable session URLs and media bytes.


### Offline local activation preflight

Before any OAuth or API call, run this read-only preflight on the machine that will execute RhemaScript:

\`\`\`bash
python -m rhemascript.integrations.preflight --audit-log "/absolute/path/in-an-existing-private-directory/youtube-audit.jsonl"
\`\`\`

The preflight:
- Checks only whether all three OAuth environment variables are present; it never prints their values.
- Checks that the audit parent directory already exists and, on POSIX, is not group/world writable.
- If the audit file already exists, checks that it is a regular file and, on POSIX, has owner-only permissions.
- Rejects a symlink audit destination.
- Does not create or modify the audit file, request OAuth, contact Google, enable the gateway, or grant publishing authority.

A successful preflight is only a local configuration check. It cannot verify Google Cloud API enablement, project billing/quota, OAuth consent, refresh-token validity, channel identity or upload permissions. Those require separate owner-led checks. Do not paste credential values or refresh tokens into terminal transcripts, issue comments, CI, or chat. Configure secrets only in the local execution environment using an appropriately protected mechanism.



## Google connection readiness checklist

Before owner-led Cloud and OAuth setup, follow [Google Connection Readiness V1](YOUTUBE_GOOGLE_CONNECTION_READINESS_V1.md). It covers the existing-project boundary, required APIs, OAuth consent/client setup, least-privilege scopes, local refresh-token handling, audit destination checks, staged read-only validation and separate publishing approval. The checklist is operational guidance only; it does not perform OAuth or verify the live Google project.


### Authority trust boundary — production blocker

The YouTube upload path requires two verifier-issued, externally signed approval credentials (`FINAL_ACCEPTANCE` and `PUBLISH`) bound to the exact project, version, request and final-film artifact, with distinct authenticated actors. The gateway revalidates the consumed approvals immediately before provider transport. This is still not production identity certification: the issuer, IdP, signing-key custody, live key registry and authorization fencing must be deployed and independently reviewed. Caller-supplied boolean fields and generic authority dictionaries are not authenticated approvals. Generic `GENERATE`, `SPEND`, and `EXTERNAL_WRITE` mutations are blocked at the gateway until signed, identity-bound operation authority is implemented. Do not expose the provider gateway to untrusted callers.

### Analytics evidence hand-off — provenance requirement

The Analytics client returns a report response; it does not by itself create verified CAP-15 evidence. A future adapter must bind the exact retained report bytes to a verified evidence version, the actual request parameters, exact video ID, and RhemaScript production version. A caller-supplied video filter or evidence-reference string alone is not proof that the report came from that query. Until that binding exists, Analytics observations are descriptive inputs only, not independently verified training evidence. Correlation must not be presented as causation.
