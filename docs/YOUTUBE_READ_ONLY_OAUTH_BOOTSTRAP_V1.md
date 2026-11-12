# RhemaScript YouTube Read-Only OAuth Bootstrap

## Purpose and authority boundary

This procedure obtains a refresh token for **YouTube channel reads only**. It is separate from the existing upload and analytics capabilities.

The bootstrap requests exactly:

`https://www.googleapis.com/auth/youtube.readonly`

It does not request YouTube Upload or YouTube Analytics scopes. It does not upload videos, change channel settings, read analytics, or publish content.

The bootstrap uses Python's standard library, an installed-app loopback redirect bound only to `127.0.0.1`, OAuth state validation, and PKCE with S256. It does not start a public web server.

## Before starting

The channel owner must confirm:

- The selected Google Cloud project is the intended RhemaScript project.
- YouTube Data API v3 is enabled in that project.
- The OAuth consent screen is configured for the intended audience.
- The Google account that manages the intended channel is listed as a test user while the app is in Testing.
- The OAuth client is the intended **Desktop app** client in the selected Google Cloud project.
- Download that exact Desktop client JSON from Google Cloud Console. Do not use the Apps Script Web application client JSON.
- Keep the downloaded JSON outside the RhemaScript repository (for example, in Downloads). Do not upload it, paste its contents, or commit it.

## Run on macOS

From Terminal:

```bash
cd "$HOME/Documents/RhemaScript"
python3 -m rhemascript.integrations.oauth_readonly \
  --client-config "$HOME/Downloads/client_secret_XXXXXXXX.json" \
  --credential-path "$HOME/.config/rhemascript/youtube-oauth.json"
```

The command reads the client ID and matching client secret from the local downloaded Desktop JSON. This avoids accidentally pairing a client ID from one OAuth client with a secret from another. The JSON is read locally and its values are never printed. The authorization-code exchange sends the matching pair only in the HTTPS POST body, alongside the PKCE verifier. Google documents the Desktop client as a public client: its client secret is not confidential, and PKCE remains the security control. The resulting credential file stores the client ID, client secret, and refresh token using the existing owner-only credential format required by RhemaScript's existing YouTube client. The file is plaintext protected by filesystem permissions, not encryption. Keep both downloaded JSON and credential file outside Git. Never paste credential values, authorization codes, tokens, or the full authorization URL into chat, a shell command, shell history, Git, or a screenshot.

The command opens the browser for Google consent. Review the permission screen. It must request only YouTube read-only access. If Google displays Upload, Analytics, channel management, or any other permission, cancel and stop.

After consent, the browser returns to a temporary loopback listener on `127.0.0.1`. The flow validates the random OAuth state and exchanges the one-time authorization code using PKCE.

The token response must explicitly report exactly the single read-only scope and include a refresh token. If Google returns broader scopes, omits a verifiable scope list, or does not return a refresh token, the command fails closed and does not write the credential file.

The credential file is created with owner-only `0600` permissions in the existing owner-only `~/.config/rhemascript` directory. It is plaintext protected by filesystem permissions, not encrypted or stored in the macOS Keychain. Do not sync or share this directory.

## Offline preflight

After the OAuth command reports success:

```bash
python3 -m rhemascript.integrations.preflight \
  --credential-file "$HOME/.config/rhemascript/youtube-oauth.json" \
  --audit-log "$HOME/.config/rhemascript/youtube-audit.jsonl"
```

The preflight is offline. It checks the local credential file and audit destination; it does not contact Google.

## Explicit read-only channel identity check

Only after reviewing the OAuth result and local preflight, run:

```bash
python3 -m rhemascript.integrations.connection \
  --credential-file "$HOME/.config/rhemascript/youtube-oauth.json" \
  --expected-channel-id "UC-3uxRbfJ2FbVQMpQnfs8ug" \
  --audit-file "$HOME/.config/rhemascript/youtube-audit.jsonl"
```

This live check refreshes the token and calls the authenticated YouTube channel-read endpoint through the IF-18 gateway. It compares the returned channel ID with the exact owner-supplied ID. Its output redacts channel details and records a redacted local audit event.

A successful identity check does not authorize uploads, thumbnail writes, analytics, deployment, or publication. Those remain separately gated and are not part of this procedure.

## Stop conditions

Stop if:

- The selected OAuth client is not the intended Desktop client.
- The consent screen requests anything beyond YouTube read-only.
- Google returns a scope set other than exactly the requested scope.
- A refresh token is not returned.
- The credential or audit directory is not owner-controlled.
- The authenticated channel ID does not match the expected channel ID.

Never share the authorization code, access token, refresh token, credential JSON, full authorization URL, or unredacted token response.
