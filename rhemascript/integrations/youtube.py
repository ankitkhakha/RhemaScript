"""Zero-cost, opt-in YouTube integration using Google's official APIs.

Credentials are injected through environment variables and never persisted here.
All consequential writes are fail-closed behind explicit publishing_authorisation.
No external request is made at import time.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
import json
import os
import re
import uuid
from urllib.request import build_opener, HTTPRedirectHandler

from rhemascript.interfaces.external import ExternalIntegrationGateway, ProviderBinding


YOUTUBE_INTERFACE_ID = "IF-18"

API_BASE = "https://www.googleapis.com/youtube/v3"
UPLOAD_BASE = "https://www.googleapis.com/upload/youtube/v3/videos"
ANALYTICS_BASE = "https://youtubeanalytics.googleapis.com/v2/reports"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REQUIRED_SCOPES = (
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/yt-analytics.readonly",
)


class YouTubeIntegrationError(RuntimeError):
    """Sanitised error for YouTube integration failures."""

def _validate_publish_at(value: Any) -> None:
    """Require a future RFC3339 timestamp with an explicit UTC offset."""
    pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise YouTubeIntegrationError("publish_at must be a future RFC3339 timestamp with an explicit timezone")
    try:
        scheduled = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise YouTubeIntegrationError("publish_at must be a valid future RFC3339 timestamp") from None
    if scheduled.tzinfo is None or scheduled.utcoffset() is None:
        raise YouTubeIntegrationError("publish_at must include an explicit timezone")
    if scheduled <= datetime.now(timezone.utc):
        raise YouTubeIntegrationError("publish_at must be in the future")


class _NoRedirect(HTTPRedirectHandler):
    """Reject redirects so credentials and media never follow an untrusted hop."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None



def _authorise_project_publish(*, evidence_pack: dict[str, Any],
                               final_film_evidence_ref: str,
                               human_director_acceptance: bool,
                               publishing_authorisation: bool) -> tuple[str, str]:
    """Validate the canonical evidence pack before permitting any YouTube write."""
    from rhemascript.evidence import validate_evidence_pack, EvidencePackError
    from rhemascript.core.authority import (
        authorise_action, final_acceptance_allowed, AuthorityError,
    )
    from rhemascript.core.gates import (
        GateDecision, GateError, GateRecord, ProjectGateState,
    )
    try:
        validated = validate_evidence_pack(evidence_pack)
        films = [
            item for item in validated.artifacts
            if item.get("artifact_type") == "EDITED_FILM"
            and item.get("status") in {"APPROVED", "VERIFIED", "ACCEPTED"}
            and (
                item.get("artifact_id") == final_film_evidence_ref
                or final_film_evidence_ref in item.get("evidence_refs", [])
            )
        ]
        if len(films) != 1:
            raise EvidencePackError(
                "final film must resolve to exactly one approved EDITED_FILM artifact"
            )
        state = ProjectGateState(validated.project_id)
        for raw in validated.gate_records:
            if not isinstance(raw, dict):
                raise GateError("gate record must be an object")
            state = state.record(GateRecord(
                project_id=raw.get("project_id", ""),
                gate=raw.get("gate", ""),
                decision=GateDecision(raw.get("decision")),
                actor_id=raw.get("actor_id", ""),
                evidence_ref=raw.get("evidence_ref", ""),
            ))
        if not state.all_gates_approved:
            raise GateError("all six project gates must be approved")
        if state.records[-1].evidence_ref != final_film_evidence_ref:
            raise GateError("final gate evidence reference does not match the approved final film")
        if not final_acceptance_allowed(
            human_director_acceptance=human_director_acceptance
        ):
            raise AuthorityError("final human acceptance is absent")
        authorise_action("PUBLISH", {
            "publishing_authorisation": publishing_authorisation
        })
        return validated.project_id, validated.project_version
    except (EvidencePackError, AuthorityError, GateError, ValueError, TypeError) as exc:
        raise YouTubeIntegrationError(
            f"operation denied by RhemaScript governance: {exc}"
        ) from None

@dataclass(frozen=True)
class YouTubeConfig:
    client_id: str
    client_secret: str
    refresh_token: str
    timeout_seconds: float = 30.0
    chunk_size: int = 8 * 1024 * 1024

    @classmethod
    def from_environment(cls) -> "YouTubeConfig":
        names = ("RHEMASCRIPT_YOUTUBE_CLIENT_ID",
                 "RHEMASCRIPT_YOUTUBE_CLIENT_SECRET",
                 "RHEMASCRIPT_YOUTUBE_REFRESH_TOKEN")
        values = [os.environ.get(name, "").strip() for name in names]
        if not all(values):
            raise YouTubeIntegrationError(
                "YouTube credentials are not configured; set the three RHEMASCRIPT_YOUTUBE_* environment variables"
            )
        return cls(*values)

    @classmethod
    def from_private_file(cls, path: str | os.PathLike[str]) -> "YouTubeConfig":
        """Load credentials from a strictly permission-checked local file."""
        from rhemascript.integrations.credentials import (
            PrivateCredentialError, load_private_credentials,
        )
        try:
            values = load_private_credentials(path)
        except PrivateCredentialError as exc:
            raise YouTubeIntegrationError(str(exc)) from None
        return cls(
            values["client_id"], values["client_secret"], values["refresh_token"]
        )

    def validate(self) -> None:
        if not all((self.client_id, self.client_secret, self.refresh_token)):
            raise YouTubeIntegrationError("OAuth configuration is incomplete")
        if not 1 <= self.timeout_seconds <= 120:
            raise YouTubeIntegrationError("timeout_seconds must be between 1 and 120")
        if (self.chunk_size < 256 * 1024 or self.chunk_size % (256 * 1024)
                or self.chunk_size > 32 * 1024 * 1024):
            raise YouTubeIntegrationError("chunk_size must be a multiple of 256 KiB between 256 KiB and 32 MiB")


def youtube_provider_binding() -> ProviderBinding:
    """Explicit Google endpoint/method contract for RhemaScript IF-18."""
    return ProviderBinding(
        interface_id=YOUTUBE_INTERFACE_ID,
        provider_name="youtube",
        endpoint="https://www.googleapis.com",
        allowed_hosts=("oauth2.googleapis.com", "www.googleapis.com",
                       "youtube.googleapis.com", "youtubeanalytics.googleapis.com"),
        operations={
            "OAUTH_TOKEN": {"method": "POST", "hosts": ("oauth2.googleapis.com",), "path_prefix": "/token"},
            "CHANNEL_READ": {"method": "GET", "hosts": ("www.googleapis.com",), "path_prefix": "/youtube/v3/channels"},
            "VIDEO_READ": {"method": "GET", "hosts": ("www.googleapis.com",), "path_prefix": "/youtube/v3/videos"},
            "ANALYTICS_READ": {"method": "GET", "hosts": ("youtubeanalytics.googleapis.com",), "path_prefix": "/v2/reports"},
            "UPLOAD_SESSION": {"method": "POST", "hosts": ("www.googleapis.com",), "path_prefix": "/upload/youtube/v3/videos"},
            "UPLOAD_CHUNK": {"method": "PUT", "hosts": ("www.googleapis.com", "youtube.googleapis.com"), "path_prefix": "/upload/youtube/v3/videos"},
            "THUMBNAIL_WRITE": {"method": "POST", "hosts": ("www.googleapis.com",), "path_prefix": "/upload/youtube/v3/thumbnails/set"},
        },
    )


class YouTubeClient:
    """Small standard-library client; no paid SDK, server, or third-party package."""

    def __init__(self, config: YouTubeConfig, *, transport=None,
                 gateway: ExternalIntegrationGateway | None = None,
                 project_id: str = "YOUTUBE-ACCOUNT",
                 source_version: str = "1.0"):
        config.validate()
        if gateway is not None and transport is not None:
            raise YouTubeIntegrationError("choose gateway or test transport, not both")
        self.config = config
        self._transport = transport
        self._gateway = gateway
        self._gateway_project_id = project_id
        self._gateway_source_version = source_version
        self._gateway_authority: dict[str, bool] = {}
        self._access_token: str | None = None

    def _request(self, url: str, *, method: str = "GET", body: bytes | None = None,
                 headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
        parsed = urlparse(url)
        allowed_hosts = {"oauth2.googleapis.com", "www.googleapis.com",
                         "youtube.googleapis.com", "youtubeanalytics.googleapis.com"}
        if (parsed.scheme != "https" or parsed.hostname not in allowed_hosts
                or parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise YouTubeIntegrationError("request URL is outside the official HTTPS Google host allowlist")
        req = Request(url, data=body, headers=headers or {}, method=method)
        try:
            if self._gateway is not None:
                path = parsed.path
                if parsed.hostname == "oauth2.googleapis.com":
                    operation = "OAUTH_TOKEN"
                elif parsed.hostname == "youtubeanalytics.googleapis.com":
                    operation = "ANALYTICS_READ"
                elif path.startswith("/upload/youtube/v3/thumbnails/set"):
                    operation = "THUMBNAIL_WRITE"
                elif path.startswith("/upload/youtube/v3/videos") and method.upper() == "PUT":
                    operation = "UPLOAD_CHUNK"
                elif path.startswith("/upload/youtube/v3/videos") and method.upper() == "POST":
                    operation = "UPLOAD_SESSION"
                elif path.startswith("/youtube/v3/channels"):
                    operation = "CHANNEL_READ"
                elif path.startswith("/youtube/v3/videos"):
                    operation = "VIDEO_READ"
                else:
                    raise YouTubeIntegrationError("request has no approved IF-18 operation")
                status, raw, response_headers = self._gateway.request(
                    YOUTUBE_INTERFACE_ID, operation, url, method=method,
                    headers=headers or {}, body=body, request_id=str(uuid.uuid4()),
                    project_id=self._gateway_project_id, source_version=self._gateway_source_version,
                    authority=self._gateway_authority,
                )
            elif self._transport:
                status, raw, response_headers = self._transport(req, self.config.timeout_seconds)
            else:
                raise YouTubeIntegrationError("live YouTube traffic requires an explicitly configured IF-18 gateway")
            if not isinstance(status, int) or not isinstance(raw, bytes) or not isinstance(response_headers, dict):
                raise YouTubeIntegrationError("transport returned an invalid response contract")
            if len(raw) > 8_000_000:
                raise YouTubeIntegrationError("YouTube response exceeds the 8 MB safety limit")
            return status, raw, response_headers
        except HTTPError as exc:
            raw = exc.read(8_000_001)
            if len(raw) > 8_000_000:
                raise YouTubeIntegrationError("YouTube response exceeds the 8 MB safety limit") from None
            return exc.code, raw, dict(exc.headers.items())
        except (URLError, TimeoutError, OSError) as exc:
            raise YouTubeIntegrationError("YouTube network request failed") from None

    def _token(self) -> str:
        if self._access_token:
            return self._access_token
        payload = urlencode({
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "refresh_token": self.config.refresh_token,
            "grant_type": "refresh_token",
        }).encode()
        status, raw, _ = self._request(
            TOKEN_URL, method="POST", body=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if status != 200:
            raise YouTubeIntegrationError("Google OAuth token refresh failed")
        try:
            token = json.loads(raw)["access_token"]
        except (ValueError, KeyError, TypeError):
            raise YouTubeIntegrationError("Google OAuth returned an invalid token response") from None
        if not isinstance(token, str) or not token:
            raise YouTubeIntegrationError("Google OAuth returned an empty access token")
        self._access_token = token
        return token

    def _authorized_request(self, url: str, *, method: str = "GET",
                            body: bytes | None = None,
                            headers: dict[str, str] | None = None):
        """Retry a 401 once only for reads; never replay a write automatically."""
        request_headers = dict(headers or {})
        status, raw, response_headers = self._request(
            url, method=method, body=body, headers=request_headers
        )
        if (status != 401 or "Authorization" not in request_headers
                or method.upper() != "GET"):
            return status, raw, response_headers
        self._access_token = None
        request_headers["Authorization"] = f"Bearer {self._token()}"
        return self._request(url, method=method, body=body, headers=request_headers)

    def _api(self, path: str, *, params: dict[str, Any] | None = None,
             method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if path.startswith("/") or ".." in path.split("/"):
            raise YouTubeIntegrationError("invalid API path")
        query = urlencode(params or {}, doseq=True)
        url = f"{API_BASE}/{path}" + (f"?{query}" if query else "")
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        status, raw, _ = self._authorized_request(url, method=method, body=body, headers=headers)
        if status not in (200, 201):
            raise YouTubeIntegrationError(f"YouTube API returned HTTP {status}")
        try:
            result = json.loads(raw)
        except ValueError:
            raise YouTubeIntegrationError("YouTube API returned invalid JSON") from None
        if not isinstance(result, dict):
            raise YouTubeIntegrationError("YouTube API returned an unexpected response")
        return result

    def channel(self) -> dict[str, Any]:
        """Return the authenticated channel's public profile fields."""
        data = self._api("channels", params={"part": "snippet,contentDetails,statistics", "mine": "true"})
        items = data.get("items", [])
        if len(items) != 1:
            raise YouTubeIntegrationError("Expected exactly one authenticated YouTube channel")
        item = items[0]
        return {key: item.get(key) for key in ("id", "snippet", "contentDetails", "statistics")}

    def verify_connection(self, *, expected_channel_id: str) -> dict[str, Any]:
        """Perform an explicit read-only OAuth/channel identity check.

        The caller must supply the expected channel ID from the owner's records.
        This method does not upload, mutate channel settings, or grant authority.
        """
        if (not isinstance(expected_channel_id, str)
                or not expected_channel_id.strip()
                or expected_channel_id.strip() != expected_channel_id):
            raise YouTubeIntegrationError("expected_channel_id must be a non-empty exact channel ID")
        data = self._api(
            "channels", params={"part": "snippet", "mine": "true"}
        )
        items = data.get("items", [])
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            raise YouTubeIntegrationError("expected exactly one authenticated YouTube channel")
        item = items[0]
        channel_id = item.get("id")
        if not isinstance(channel_id, str) or not channel_id:
            raise YouTubeIntegrationError("Google returned an invalid channel identity")
        if channel_id != expected_channel_id:
            raise YouTubeIntegrationError(
                "authenticated YouTube channel does not match the expected channel ID"
            )
        snippet = item.get("snippet")
        title = snippet.get("title") if isinstance(snippet, dict) else None
        return {
            "authenticated": True,
            "channel_id": channel_id,
            "channel_title": title if isinstance(title, str) else None,
            "read_only": True,
        }

    def upload_video(self, file_path: str, *, title: str, description: str,
                     evidence_pack: dict[str, Any],
                     final_film_evidence_ref: str,
                     human_director_acceptance: bool,
                     tags: list[str] | None = None, category_id: str = "22",
                     privacy_status: str = "private", publish_at: str | None = None,
                     made_for_kids: bool = False,
                     publishing_authorisation: bool = False) -> dict[str, Any]:
        """Resumable upload behind all six project gates and separate authorities.

        The caller must supply ordered, approved gate records for this project,
        final-film evidence matching the last gate, final human acceptance, and
        separate publishing authorisation. The safe default is private.
        """
        project_id, project_version = _authorise_project_publish(
            evidence_pack=evidence_pack,
            final_film_evidence_ref=final_film_evidence_ref,
            human_director_acceptance=human_director_acceptance,
            publishing_authorisation=publishing_authorisation,
        )
        self._gateway_project_id = project_id
        self._gateway_source_version = project_version
        self._gateway_authority = {"publishing_authorisation": publishing_authorisation}
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size == 0:
            raise YouTubeIntegrationError("video file is missing or empty")
        if not isinstance(title, str) or not title.strip() or len(title) > 100:
            raise YouTubeIntegrationError("title must contain 1 to 100 characters")
        if not isinstance(description, str) or len(description) > 5000:
            raise YouTubeIntegrationError("description exceeds the supported limit")
        if privacy_status not in {"private", "unlisted", "public"}:
            raise YouTubeIntegrationError("invalid privacy_status")
        if publish_at is not None:
            if privacy_status != "private":
                raise YouTubeIntegrationError("scheduled publication requires private privacy")
            _validate_publish_at(publish_at)
        if not isinstance(made_for_kids, bool):
            raise YouTubeIntegrationError("made_for_kids must be explicitly boolean")
        if tags is not None and (not isinstance(tags, list) or any(not isinstance(x, str) for x in tags)):
            raise YouTubeIntegrationError("tags must be a list of strings")

        metadata: dict[str, Any] = {
            "snippet": {"title": title.strip(), "description": description,
                        "categoryId": str(category_id), "tags": tags or []},
            "status": {"privacyStatus": privacy_status, "selfDeclaredMadeForKids": made_for_kids},
        }
        if publish_at:
            metadata["status"]["publishAt"] = publish_at
        query = urlencode({"uploadType": "resumable", "part": "snippet,status"})
        headers = {
            "Authorization": f"Bearer {self._token()}",
            "Content-Type": "application/json; charset=UTF-8",
            "X-Upload-Content-Type": "video/*",
            "X-Upload-Content-Length": str(path.stat().st_size),
        }
        status, raw, response_headers = self._authorized_request(
            f"{UPLOAD_BASE}?{query}", method="POST",
            body=json.dumps(metadata).encode(), headers=headers,
        )
        location = response_headers.get("Location") or response_headers.get("location")
        if status not in (200, 201) or not location:
            raise YouTubeIntegrationError("YouTube did not create a resumable upload session")
        parsed = urlparse(location)
        if (parsed.scheme != "https" or parsed.hostname not in {"www.googleapis.com", "youtube.googleapis.com"}
                or parsed.username or parsed.password or parsed.port not in (None, 443)
                or parsed.fragment):
            raise YouTubeIntegrationError("YouTube returned an untrusted upload-session URL")

        total = path.stat().st_size
        offset = 0
        final_raw = b""
        with path.open("rb") as video:
            while offset < total:
                chunk = video.read(min(self.config.chunk_size, total - offset))
                end = offset + len(chunk) - 1
                chunk_headers = {
                    "Authorization": f"Bearer {self._token()}",
                    "Content-Type": "video/*",
                    "Content-Length": str(len(chunk)),
                    "Content-Range": f"bytes {offset}-{end}/{total}",
                }
                status, final_raw, chunk_response_headers = self._authorized_request(
                    location, method="PUT", body=chunk, headers=chunk_headers,
                )
                if status in (200, 201):
                    offset = total
                elif status == 308:
                    acknowledged = (chunk_response_headers.get("Range") or chunk_response_headers.get("range"))
                    if acknowledged and "-" in acknowledged:
                        try:
                            acknowledged_end = int(acknowledged.rsplit("-", 1)[1])
                        except ValueError:
                            raise YouTubeIntegrationError("upload server returned an invalid byte range") from None
                        # The server may acknowledge only part of the submitted chunk.
                        # Never skip unacknowledged bytes or accept an impossible offset.
                        if acknowledged_end < offset or acknowledged_end > end:
                            raise YouTubeIntegrationError("upload server acknowledged an impossible byte range")
                        next_offset = acknowledged_end + 1
                    else:
                        # A 308 without Range means no byte range was acknowledged.
                        next_offset = offset
                    if next_offset <= offset:
                        raise YouTubeIntegrationError("upload made no forward progress; refusing an upload loop")
                    offset = next_offset
                    video.seek(offset)
                else:
                    raise YouTubeIntegrationError(f"resumable upload returned HTTP {status}")
        try:
            result = json.loads(final_raw)
            video_id = result["id"]
        except (ValueError, KeyError, TypeError):
            raise YouTubeIntegrationError("upload completed without a verifiable video ID") from None
        if not isinstance(video_id, str) or not video_id:
            raise YouTubeIntegrationError("upload response contained an invalid video ID")
        return {"video_id": video_id, "url": f"https://www.youtube.com/watch?v={video_id}",
                "privacy_status_requested": privacy_status, "publish_at_requested": publish_at,
                "upload_completed": True, "verification_required": True}

    def set_thumbnail(self, video_id: str, image_path: str, *,
                      evidence_pack: dict[str, Any],
                      final_film_evidence_ref: str,
                      human_director_acceptance: bool,
                      publishing_authorisation: bool = False) -> dict[str, Any]:
        project_id, project_version = _authorise_project_publish(
            evidence_pack=evidence_pack,
            final_film_evidence_ref=final_film_evidence_ref,
            human_director_acceptance=human_director_acceptance,
            publishing_authorisation=publishing_authorisation,
        )
        self._gateway_project_id = project_id
        self._gateway_source_version = project_version
        self._gateway_authority = {"publishing_authorisation": publishing_authorisation}
        path = Path(image_path)
        if not path.is_file():
            raise YouTubeIntegrationError("thumbnail file does not exist")
        suffix = path.suffix.lower()
        mime_by_suffix = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
        mime = mime_by_suffix.get(suffix)
        if mime is None:
            raise YouTubeIntegrationError("thumbnail must use a PNG or JPEG file extension")
        # YouTube custom thumbnails are limited to 2 MB. Read one byte beyond
        # the limit so a file that grows after stat() is still rejected.
        try:
            with path.open("rb") as image:
                thumbnail_bytes = image.read(2 * 1024 * 1024 + 1)
        except OSError:
            raise YouTubeIntegrationError("thumbnail file could not be read") from None
        if not thumbnail_bytes or len(thumbnail_bytes) > 2 * 1024 * 1024:
            raise YouTubeIntegrationError("thumbnail must be non-empty and no larger than 2 MB")
        url = f"https://www.googleapis.com/upload/youtube/v3/thumbnails/set?{urlencode({'videoId': video_id})}"
        status, raw, _ = self._authorized_request(url, method="POST", body=thumbnail_bytes,
            headers={"Authorization": f"Bearer {self._token()}", "Content-Type": mime})
        if status not in (200, 201):
            raise YouTubeIntegrationError(f"thumbnail upload returned HTTP {status}")
        return json.loads(raw)

    def verify_video(self, video_id: str) -> dict[str, Any]:
        """Read back one exact video ID and return only validated status fields."""
        if not isinstance(video_id, str) or not video_id.strip() or video_id != video_id.strip():
            raise YouTubeIntegrationError("video_id must be a non-empty exact ID")
        data = self._api("videos", params={"part": "snippet,status,processingDetails", "id": video_id})
        items = data.get("items", [])
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            raise YouTubeIntegrationError("video ID was not found during verification")
        item = items[0]
        if item.get("id") != video_id:
            raise YouTubeIntegrationError("YouTube returned a different video ID during verification")
        snippet = item.get("snippet")
        status = item.get("status")
        processing = item.get("processingDetails")
        if not isinstance(snippet, dict) or not isinstance(status, dict) or not isinstance(processing, dict):
            raise YouTubeIntegrationError("YouTube returned incomplete video verification details")
        title = snippet.get("title")
        privacy_status = status.get("privacyStatus")
        upload_status = status.get("uploadStatus")
        processing_status = processing.get("processingStatus")
        if not isinstance(title, str) or not isinstance(privacy_status, str):
            raise YouTubeIntegrationError("YouTube returned invalid video metadata during verification")
        if upload_status is not None and not isinstance(upload_status, str):
            raise YouTubeIntegrationError("YouTube returned an invalid upload status")
        if processing_status is not None and not isinstance(processing_status, str):
            raise YouTubeIntegrationError("YouTube returned an invalid processing status")
        return {"video_id": video_id, "title": title, "privacy_status": privacy_status,
                "upload_status": upload_status, "processing_status": processing_status}

    def analytics(self, *, start_date: date, end_date: date,
                  metrics: str = "views,estimatedMinutesWatched,averageViewDuration,subscribersGained",
                  dimensions: str = "day", filters: str | None = None) -> dict[str, Any]:
        if end_date < start_date:
            raise YouTubeIntegrationError("end_date cannot precede start_date")
        params: dict[str, Any] = {
            "ids": "channel==MINE", "startDate": start_date.isoformat(),
            "endDate": end_date.isoformat(), "metrics": metrics, "dimensions": dimensions,
        }
        if filters:
            params["filters"] = filters
        return self._analytics_api(params)

    def _analytics_api(self, params: dict[str, Any]) -> dict[str, Any]:
        query = urlencode(params)
        status, raw, _ = self._authorized_request(
            f"{ANALYTICS_BASE}?{query}",
            headers={"Authorization": f"Bearer {self._token()}", "Accept": "application/json"},
        )
        if status != 200:
            raise YouTubeIntegrationError(f"YouTube Analytics API returned HTTP {status}")
        try:
            result = json.loads(raw)
        except ValueError:
            raise YouTubeIntegrationError("YouTube Analytics API returned invalid JSON") from None
        if not isinstance(result, dict):
            raise YouTubeIntegrationError("YouTube Analytics API returned an unexpected response")
        return result
