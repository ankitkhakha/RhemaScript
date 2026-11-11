"""Zero-cost, opt-in YouTube integration using Google's official APIs.

Credentials are injected through environment variables and never persisted here.
All consequential writes are fail-closed behind explicit publishing_authorisation.
No external request is made at import time.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
import json
import os
import uuid


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

    def validate(self) -> None:
        if not all((self.client_id, self.client_secret, self.refresh_token)):
            raise YouTubeIntegrationError("OAuth configuration is incomplete")
        if not 1 <= self.timeout_seconds <= 120:
            raise YouTubeIntegrationError("timeout_seconds must be between 1 and 120")
        if self.chunk_size < 256 * 1024 or self.chunk_size % (256 * 1024):
            raise YouTubeIntegrationError("chunk_size must be a multiple of 256 KiB")


class YouTubeClient:
    """Small standard-library client; no paid SDK, server, or third-party package."""

    def __init__(self, config: YouTubeConfig, *, transport=None):
        config.validate()
        self.config = config
        self._transport = transport
        self._access_token: str | None = None

    def _request(self, url: str, *, method: str = "GET", body: bytes | None = None,
                 headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
        req = Request(url, data=body, headers=headers or {}, method=method)
        try:
            if self._transport:
                return self._transport(req, self.config.timeout_seconds)
            with urlopen(req, timeout=self.config.timeout_seconds) as response:
                return response.status, response.read(8_000_001), dict(response.headers.items())
        except HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace")
            raise YouTubeIntegrationError(
                f"YouTube request failed ({exc.code}); response: {detail[:1000]}"
            ) from None
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
        status, raw, _ = self._request(url, method=method, body=body, headers=headers)
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

    def upload_video(self, file_path: str, *, title: str, description: str,
                     tags: list[str] | None = None, category_id: str = "22",
                     privacy_status: str = "private", publish_at: str | None = None,
                     made_for_kids: bool = False, publishing_authorisation: bool = False) -> dict[str, Any]:
        """Resumable upload. Public/scheduled publishing requires explicit authority.

        The safe default is private. publish_at is accepted only with private privacy.
        """
        from rhemascript.core.authority import authorise_action, AuthorityError
        try:
            authorise_action("PUBLISH", {"publishing_authorisation": publishing_authorisation})
        except AuthorityError as exc:
            raise YouTubeIntegrationError("upload denied: publishing authorisation is absent") from exc
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size == 0:
            raise YouTubeIntegrationError("video file is missing or empty")
        if not isinstance(title, str) or not title.strip() or len(title) > 100:
            raise YouTubeIntegrationError("title must contain 1 to 100 characters")
        if not isinstance(description, str) or len(description) > 5000:
            raise YouTubeIntegrationError("description exceeds the supported limit")
        if privacy_status not in {"private", "unlisted", "public"}:
            raise YouTubeIntegrationError("invalid privacy_status")
        if publish_at and (privacy_status != "private" or not isinstance(publish_at, str)):
            raise YouTubeIntegrationError("scheduled publication requires private privacy and an RFC3339 publish_at")
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
        status, raw, response_headers = self._request(
            f"{UPLOAD_BASE}?{query}", method="POST",
            body=json.dumps(metadata).encode(), headers=headers,
        )
        location = response_headers.get("Location") or response_headers.get("location")
        if status not in (200, 201) or not location:
            raise YouTubeIntegrationError("YouTube did not create a resumable upload session")
        parsed = urlparse(location)
        if parsed.scheme != "https" or parsed.hostname not in {"www.googleapis.com", "youtube.googleapis.com"}:
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
                status, final_raw, _ = self._request(
                    location, method="PUT", body=chunk, headers=chunk_headers,
                )
                if status in (200, 201):
                    offset = total
                elif status == 308:
                    offset = end + 1
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
                "upload_verified": True}

    def set_thumbnail(self, video_id: str, image_path: str, *, publishing_authorisation: bool = False) -> dict[str, Any]:
        from rhemascript.core.authority import authorise_action, AuthorityError
        try:
            authorise_action("PUBLISH", {"publishing_authorisation": publishing_authorisation})
        except AuthorityError as exc:
            raise YouTubeIntegrationError("thumbnail update denied: publishing authorisation is absent") from exc
        path = Path(image_path)
        if not path.is_file():
            raise YouTubeIntegrationError("thumbnail file does not exist")
        mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
        url = f"https://www.googleapis.com/upload/youtube/v3/thumbnails/set?{urlencode({'videoId': video_id})}"
        status, raw, _ = self._request(url, method="POST", body=path.read_bytes(),
            headers={"Authorization": f"Bearer {self._token()}", "Content-Type": mime})
        if status not in (200, 201):
            raise YouTubeIntegrationError(f"thumbnail upload returned HTTP {status}")
        return json.loads(raw)

    def verify_video(self, video_id: str) -> dict[str, Any]:
        data = self._api("videos", params={"part": "snippet,status,processingDetails", "id": video_id})
        items = data.get("items", [])
        if len(items) != 1:
            raise YouTubeIntegrationError("video ID was not found during verification")
        item = items[0]
        return {"video_id": item.get("id"), "title": item.get("snippet", {}).get("title"),
                "privacy_status": item.get("status", {}).get("privacyStatus"),
                "upload_status": item.get("status", {}).get("uploadStatus"),
                "processing_status": item.get("processingDetails", {}).get("processingStatus")}

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
        status, raw, _ = self._request(
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
