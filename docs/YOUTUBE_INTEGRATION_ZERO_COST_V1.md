# RhemaScript YouTube Integration — zero-cost implementation

## Scope

This integration uses only Python's standard library and Google's official YouTube Data API v3 and YouTube Analytics API. It adds no package dependency, paid API, hosted service, or database. It does not create a Google Cloud project, enable an API, request OAuth consent, or store credentials.

Implemented client operations:
- Read the authenticated channel profile.
- Resumable video upload with title, description, tags, category, privacy and optional scheduled publication metadata.
- Set a custom thumbnail.
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
    human_director_acceptance=True,
    tags=["RhemaScript", "Bible"],
    privacy_status="private",
    publishing_authorisation=True,
)
verified = client.verify_video(uploaded["video_id"])
```

For a scheduled public release, YouTube requires the upload to be private and a valid future RFC3339 `publish_at` value. The client enforces private privacy when `publish_at` is supplied.

## Remaining external activation and assurance

A real channel connection and upload cannot be verified until the owner configures OAuth and explicitly authorises a test upload. API access, OAuth consent, channel permissions, quota and account-specific restrictions must be confirmed in the user's existing Google project. No live upload, thumbnail change, public release, or analytics access has been performed by this code change.

The existing interface gateway and project approval system remain intact. Do not add credentials to source control, CI variables, issue comments or pull requests. Before production use, add a local encrypted secret store if the deployment environment provides one; this implementation intentionally reads secrets from environment variables only.

## External gateway integration status

The YouTube client is now routed through the existing provider-neutral external gateway when an IF-18 gateway is explicitly supplied. The provider binding declares the supported Google hosts, API path families, and HTTP methods for OAuth, channel/video reads, analytics, resumable upload sessions, upload chunks, and thumbnail writes. The client refuses live traffic if neither an explicitly configured gateway nor an injected offline test transport is supplied.

The gateway extension preserves the original JSON POST invoke contract and adds a separate method-aware request path for OAuth and resumable protocols. Each provider request is audited without recording query values, authorization headers, OAuth body contents, upload-session URLs, or media bytes. Upload-session, upload-chunk, and thumbnail operations are checked against the separate PUBLISH authority at the gateway boundary. The YouTube client independently validates the Evidence Pack, all six ordered gates, final-film evidence, and human final acceptance before any publishing write.

Automated CI has passed for the IF-18 gateway routing and fail-closed tests, the mocked end-to-end resumable upload (including binary chunk acknowledgements and final video verification), and the mocked gateway-backed thumbnail write. A path-segment boundary hardening test also verifies that sibling paths outside an operation's declared prefix are rejected before transport. These are mocked contract tests, not live Google account or provider validation.

`JsonlAuditSink` is the included standard-library local audit sink. It appends JSON Lines metadata, accepts only a strict allowlist of audit fields, rejects payload/header/credential fields, creates or tightens the log file to owner-only permissions (0600), rejects symlink destinations where the platform supports `O_NOFOLLOW`, and calls `fsync` before returning. Its parent directory must already exist and be controlled by the operator. This is a local append-only log, not tamper-proof remote archival; protect and back up the containing directory according to the project's retention policy. Do not set enabled=True until the owner has reviewed the provider binding, selected and protected the audit-log location, configured the OAuth environment, and explicitly chosen to enable external requests. No OAuth consent, channel connection, live upload, thumbnail change, analytics query, public release, merge, or deployment has been performed. A passing CI run validates mocked contracts only; it does not validate account permissions, quota, billing status, or real Google responses.


### Local audit sink

The included `JsonlAuditSink` is exported from `rhemascript.integrations`. Example:

```python
from rhemascript.integrations import JsonlAuditSink

audit_sink = JsonlAuditSink("/absolute/path/in-an-existing-private-directory/youtube-audit.jsonl")
```

The sink does not create parent directories. Keep the log on a local filesystem with appropriate access controls; do not put it in a shared repository, public web root, or CI artifact. Each record is synchronously flushed and fsynced. The event schema excludes request bodies, headers, OAuth values, query values, resumable session URLs and media bytes.
