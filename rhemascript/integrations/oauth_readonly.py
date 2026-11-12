"""Least-privilege Google OAuth bootstrap for YouTube channel read verification.

Uses the installed-app loopback flow with PKCE. Requests exactly
youtube.readonly, requires Google's returned scope set to match exactly, and
writes the refresh token only to the existing owner-only credential store.
No publishing, analytics, or channel mutation is performed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import webbrowser

from rhemascript.integrations.credentials import (
    PrivateCredentialError,
    write_private_credentials,
)

AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
READ_ONLY_SCOPE = "https://www.googleapis.com/auth/youtube.readonly"
CALLBACK_PATH = "/oauth2callback"
DEFAULT_CREDENTIAL_PATH = "~/.config/rhemascript/youtube-oauth.json"
MAX_RESPONSE_BYTES = 64_000


class OAuthBootstrapError(RuntimeError):
    """Sanitised OAuth bootstrap failure; never includes credential values."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _create_pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _validate_token_response(payload: Any) -> tuple[str, str]:
    """Return access/refresh tokens only for an exact read-only scope grant."""
    if not isinstance(payload, dict):
        raise OAuthBootstrapError("Google returned an invalid OAuth token response")
    granted = payload.get("scope")
    if not isinstance(granted, str):
        raise OAuthBootstrapError("Google did not return a verifiable granted-scope list")
    scopes = granted.split()
    if len(scopes) != 1 or scopes[0] != READ_ONLY_SCOPE:
        raise OAuthBootstrapError("Google granted scopes outside the exact YouTube read-only request")
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    token_type = payload.get("token_type")
    if not isinstance(access_token, str) or not access_token:
        raise OAuthBootstrapError("Google did not return a valid access token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise OAuthBootstrapError(
            "Google did not return a refresh token; no credential file was written"
        )
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise OAuthBootstrapError("Google returned an unsupported token type")
    return access_token, refresh_token


def _exchange_code(*, client_id: str, code: str,
                   redirect_uri: str, verifier: str, timeout: float = 30.0) -> dict[str, Any]:
    body = urlencode({
        "client_id": client_id,
        "code": code,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }).encode("ascii")
    request = Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
        method="POST",
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise OAuthBootstrapError("Google OAuth token exchange was rejected")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise OAuthBootstrapError("Google OAuth response exceeded the safety limit")
    except HTTPError as exc:
        # Read only Google's machine-readable error code. Never surface the
        # response description/body, which may contain sensitive provider data.
        category = "token_rejected"
        try:
            error_body = exc.read(MAX_RESPONSE_BYTES + 1)
            if len(error_body) <= MAX_RESPONSE_BYTES:
                error_payload = json.loads(error_body.decode("utf-8"))
                candidate = error_payload.get("error") if isinstance(error_payload, dict) else None
                safe_errors = {
                    "invalid_client", "invalid_grant", "redirect_uri_mismatch",
                    "unauthorized_client", "unsupported_grant_type",
                    "invalid_request", "invalid_scope",
                }
                if isinstance(candidate, str) and candidate in safe_errors:
                    category = candidate
        except (UnicodeDecodeError, ValueError, OSError):
            pass
        raise OAuthBootstrapError(
            f"Google OAuth token exchange rejected (HTTP {exc.code}, {category}); "
            "no credentials were saved"
        ) from None
    except (URLError, TimeoutError, OSError):
        raise OAuthBootstrapError("Google OAuth token exchange could not reach Google") from None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise OAuthBootstrapError("Google returned an invalid OAuth token response") from None
    if not isinstance(payload, dict):
        raise OAuthBootstrapError("Google returned an invalid OAuth token response")
    return payload


def _safe_callback_error_category(category: str) -> str:
    """Return a fixed, non-sensitive callback diagnostic category."""
    safe_categories = {
        "invalid_request", "invalid_query", "unexpected_parameters",
        "duplicate_parameters", "scope_mismatch", "invalid_issuer",
        "state_mismatch", "authorization_denied",
        "authorization_error_details", "missing_code",
    }
    return category if category in safe_categories else "callback_rejected"


def _receive_loopback_code(*, client_id: str, timeout_seconds: int = 300) -> tuple[str, str, str]:
    """Run a one-shot 127.0.0.1 callback and return code, verifier, redirect URI."""
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 900:
        raise OAuthBootstrapError("OAuth callback timeout must be between 1 and 900 seconds")
    verifier, challenge = _create_pkce_pair()
    state = secrets.token_urlsafe(32)
    result: dict[str, str] = {}

    class _LoopbackHTTPServer(HTTPServer):
        request_queue_size = 1

    server = _LoopbackHTTPServer(("127.0.0.1", 0), _callback_handler(result, state))
    server.timeout = 1.0
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}{CALLBACK_PATH}"
    authorization_uri = AUTHORIZATION_URL + "?" + urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": READ_ONLY_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "false",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    print("Opening Google authorization in your browser.")
    print("If it does not open, copy this URL into your browser:")
    print(authorization_uri)
    webbrowser.open(authorization_uri)
    deadline = time.monotonic() + timeout_seconds
    try:
        while not result and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if "error" in result:
        # Emit only a fixed internal category; never include callback values.
        category = _safe_callback_error_category(result["error"])
        raise OAuthBootstrapError(
            f"Google callback rejected ({category}); no credentials were saved"
        )
    if "code" not in result:
        raise OAuthBootstrapError("Timed out waiting for the local Google OAuth callback")
    return result["code"], verifier, redirect_uri


def _callback_handler(result: dict[str, str], expected_state: str):
    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Reject oversized or non-GET-style callback requests before parsing.
            if len(self.path) > 8192 or self.headers.get("Transfer-Encoding"):
                result["error"] = "invalid_request"
                self._reply(400, "Authorization response rejected. You may close this tab.")
                return
            if result:
                self._reply(409, "This authorization callback has already been handled.")
                return
            parsed = urlparse(self.path)
            if parsed.path != CALLBACK_PATH or parsed.fragment:
                self.send_error(404)
                return
            try:
                query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=8)
            except ValueError:
                result["error"] = "invalid_query"
                self._reply(400, "Authorization response rejected. You may close this tab.")
                return
            # Google includes the RFC 9207 issuer parameter (iss) in its
            # authorization response. Accept it only once and only for Google's
            # exact issuer; continue rejecting every other unexpected parameter.
            # Google may include standard authorization-response context
            # parameters alongside code/state. Allow only documented fields;
            # validate security-relevant values and reject duplicates.
            allowed = {
                "state", "code", "error", "error_description", "error_uri",
                "iss", "scope", "authuser", "prompt",
            }
            if set(query) - allowed:
                result["error"] = "unexpected_parameters"
                self._reply(400, "Authorization response rejected. You may close this tab.")
                return
            for optional_singleton in ("scope", "authuser", "prompt", "iss"):
                values = query.get(optional_singleton, [])
                if len(values) > 1:
                    result["error"] = "duplicate_parameters"
                    self._reply(400, "Authorization response rejected. You may close this tab.")
                    return
            returned_scopes = query.get("scope", [])
            if returned_scopes:
                scopes = returned_scopes[0].split()
                if scopes != [READ_ONLY_SCOPE]:
                    result["error"] = "scope_mismatch"
                    self._reply(400, "Authorization response rejected. You may close this tab.")
                    return
            issuers = query.get("iss", [])
            if issuers and (len(issuers) != 1 or issuers[0] != "https://accounts.google.com"):
                result["error"] = "invalid_issuer"
                self._reply(400, "Authorization response rejected. You may close this tab.")
                return
            states = query.get("state", [])
            if len(states) != 1 or not hmac.compare_digest(states[0], expected_state):
                result["error"] = "state_mismatch"
                self._reply(400, "Authorization response rejected. You may close this tab.")
                return
            errors = query.get("error", [])
            if errors:
                result["error"] = "authorization_denied"
                self._reply(400, "Authorization was not completed. You may close this tab.")
                return
            if query.get("error_description") or query.get("error_uri"):
                # Never expose provider-supplied error details in the local callback page.
                result["error"] = "authorization_error_details"
                self._reply(400, "Authorization was not completed. You may close this tab.")
                return
            codes = query.get("code", [])
            if len(codes) != 1 or not codes[0] or len(codes[0]) > 4096:
                result["error"] = "missing_code"
                self._reply(400, "Authorization response was incomplete. You may close this tab.")
                return
            result["code"] = codes[0]
            self._reply(200, "RhemaScript read-only authorization received. You may close this tab.")

        def _reply(self, status: int, message: str):
            body = ("<!doctype html><html><head><meta charset='utf-8'>"
                    "<title>RhemaScript OAuth</title></head><body><p>" +
                    message + "</p></body></html>").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return CallbackHandler


def run_bootstrap(*, client_id: str,
                  credential_path: str | Path = DEFAULT_CREDENTIAL_PATH,
                  timeout_seconds: int = 300) -> None:
    if not isinstance(client_id, str) or not client_id.strip():
        raise OAuthBootstrapError("OAuth desktop client ID is required")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 900:
        raise OAuthBootstrapError("OAuth callback timeout must be between 1 and 900 seconds")
    target = Path(credential_path).expanduser()
    if target.exists() or target.is_symlink():
        raise OAuthBootstrapError("credential destination already exists; refusing to overwrite it")
    code, verifier, redirect_uri = _receive_loopback_code(
        client_id=client_id.strip(), timeout_seconds=timeout_seconds
    )
    payload = _exchange_code(
        client_id=client_id.strip(),
        code=code, redirect_uri=redirect_uri, verifier=verifier,
    )
    _access_token, refresh_token = _validate_token_response(payload)
    try:
        write_private_credentials(
            credential_path,
            client_id=client_id.strip(),
            refresh_token=refresh_token,
        )
    except PrivateCredentialError as exc:
        raise OAuthBootstrapError(str(exc)) from None
    print("Read-only OAuth credentials saved in the owner-only local credential file.")
    print("Granted scope: YouTube read-only only.")
    print("No upload, analytics, publishing, or channel-write permission was requested.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authorize RhemaScript for YouTube channel reads only"
    )
    parser.add_argument("--client-id", help="Desktop OAuth client ID")
    parser.add_argument("--credential-path", default=DEFAULT_CREDENTIAL_PATH,
                        help="new private credential file path (must not already exist)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="seconds to wait for the browser callback (default: 300)")
    args = parser.parse_args(argv)
    try:
        client_id = (args.client_id or input("Google Desktop OAuth client ID: ")).strip()
        run_bootstrap(
            client_id=client_id,
            credential_path=args.credential_path,
            timeout_seconds=args.timeout,
        )
    except (OAuthBootstrapError, PrivateCredentialError, EOFError, KeyboardInterrupt) as exc:
        print("OAuth bootstrap stopped safely; no credential values were displayed.")
        if isinstance(exc, OAuthBootstrapError):
            print(f"Reason: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
