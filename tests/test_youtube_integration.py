import os
import tempfile
import unittest
from datetime import date
from unittest.mock import patch

from rhemascript.integrations.youtube import (
    YouTubeClient, YouTubeConfig, YouTubeIntegrationError,
)


class YouTubeIntegrationTests(unittest.TestCase):
    def config(self):
        return YouTubeConfig("client-id", "client-secret", "refresh-token")

    def publish_context(self, *, authorised=True):
        gates = (
            "PROJECT_CREATIVE_DIRECTION", "SCRIPT_BIBLICAL_ACCURACY",
            "VISUAL_DEVELOPMENT", "PRODUCTION_PLAN_PROMPT",
            "GENERATION_AUTHORISATION", "FINAL_FILM",
        )
        records = [
            {"project_id": "RS-TEST-001", "gate": gate, "decision": "APPROVED",
             "actor_id": "human-director", "evidence_ref": f"evidence:{gate}"}
            for gate in gates
        ]
        kinds = (
            "BIBLICAL_SOURCE", "APPROVED_SCRIPT", "APPROVED_NARRATION",
            "STORYBOARD", "AUDIO_VISUAL_PLAN", "PROMPT", "ASSET", "EDITED_FILM",
        )
        artifacts = []
        links = []
        previous = None
        for index, kind in enumerate(kinds):
            ident = f"ART-{index + 1}"
            artifacts.append({
                "artifact_id": ident, "project_id": "RS-TEST-001",
                "project_version": "1.0", "artifact_type": kind,
                "version": "1", "status": "APPROVED",
                "evidence_refs": ["evidence:FINAL_FILM"] if kind == "EDITED_FILM" else [],
            })
            if previous is not None:
                links.append({"from_artifact_id": previous, "to_artifact_id": ident,
                              "relationship": "derived_from"})
            previous = ident
        evidence_pack = {
            "manifest_id": "RS-MANIFEST-TEST", "schema_version": "1.0",
            "project_record": {
                "record_id": "RS-EVIDENCE-TEST", "record_type": "SYNTHETIC_PROJECT",
                "schema_version": "1.0", "project_id": "RS-TEST-001",
                "status": "DRAFT", "classification": "OPERATIONAL", "version": "1.0",
            },
            "artifacts": artifacts,
            "evidence_records": [{
                "evidence_id": "EV-TEST", "capability_id": "CAP-01",
                "payload": {"sources": [{"source_ref": "bible:ref"}]},
                "evidence_refs": ["bible:ref"], "artifact_refs": ["ART-1"],
            }],
            "source_to_final_links": links,
            "gate_records": records,
        }
        return {
            "evidence_pack": evidence_pack,
            "final_film_evidence_ref": "evidence:FINAL_FILM",
            "human_director_acceptance": True,
            "publishing_authorisation": authorised,
        }

    def test_missing_credentials_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(YouTubeIntegrationError):
                YouTubeConfig.from_environment()

    def test_expired_access_token_is_refreshed_once(self):
        calls = {"tokens": 0, "channel": 0}
        def transport(request, timeout):
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                calls["tokens"] += 1
                return 200, b'{"access_token":"fresh-token"}', {}
            if request.full_url.startswith("https://www.googleapis.com/youtube/v3/channels"):
                calls["channel"] += 1
                if calls["channel"] == 1:
                    return 401, b'{"error":"invalid_token"}', {}
                self.assertEqual(request.get_header("Authorization"), "Bearer fresh-token")
                return 200, b'{"items":[{"id":"channel-1"}]}', {}
            self.fail("unexpected request")
        client = YouTubeClient(self.config(), transport=transport)
        result = client.channel()
        self.assertEqual(result["id"], "channel-1")
        self.assertEqual(calls, {"tokens": 2, "channel": 2})

    def test_oversized_transport_response_is_rejected(self):
        client = YouTubeClient(self.config(), transport=lambda *args: (200, b"x" * 8_000_001, {}))
        with self.assertRaisesRegex(YouTubeIntegrationError, "8 MB safety limit"):
            client.channel()

    def test_invalid_chunk_size_rejected(self):
        with self.assertRaises(YouTubeIntegrationError):
            YouTubeConfig("id", "secret", "refresh", chunk_size=1000).validate()

    def test_import_and_client_creation_do_not_make_network_calls(self):
        calls = []
        client = YouTubeClient(self.config(), transport=lambda *args: calls.append(args))
        self.assertEqual(calls, [])
        self.assertIsNotNone(client)

    def test_upload_requires_explicit_publishing_authority(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "publishing_authorisation"):
                client.upload_video(video.name, title="Approved", description="Test",
                                    **self.publish_context(authorised=False))

    def test_thumbnail_write_requires_full_project_authority(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.publish_context(authorised=False)
        with self.assertRaisesRegex(YouTubeIntegrationError, "publishing_authorisation"):
            client.set_thumbnail("video-123", "/not/read.png", **context)

    def test_final_gate_must_reference_the_approved_final_film(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.publish_context()
        context["evidence_pack"]["gate_records"][-1]["evidence_ref"] = "evidence:OTHER-FILM"
        with self.assertRaisesRegex(YouTubeIntegrationError, "does not match the approved final film"):
            client.upload_video("/not/read.mp4", title="Approved", description="Test", **context)

    def test_thumbnail_write_rejects_out_of_order_gate_records(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.publish_context()
        context["evidence_pack"]["gate_records"][0], context["evidence_pack"]["gate_records"][1] = (
            context["evidence_pack"]["gate_records"][1],
            context["evidence_pack"]["gate_records"][0],
        )
        with self.assertRaisesRegex(YouTubeIntegrationError, "expected gate"):
            client.set_thumbnail("video-123", "/not/read.png", **context)

    def test_invalid_video_metadata_is_rejected_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "1 to 100"):
                client.upload_video(video.name, title="", description="Test",
                                    **self.publish_context())

    def test_scheduled_publication_must_use_private_upload(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "requires private privacy"):
                client.upload_video(video.name, title="Approved", description="Test",
                    privacy_status="public", publish_at="2026-12-01T12:00:00Z",
                    **self.publish_context())

    def test_analytics_date_range_is_validated_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with self.assertRaisesRegex(YouTubeIntegrationError, "cannot precede"):
            client.analytics(start_date=date(2026, 12, 2), end_date=date(2026, 12, 1))

    def test_resumable_upload_retries_unacknowledged_bytes(self):
        chunk_size = 256 * 1024
        payload = bytes((i % 251 for i in range(chunk_size * 2)))
        put_requests = []

        def transport(request, timeout):
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                return 200, b'{"access_token":"test-token"}', {}
            if request.full_url.startswith("https://www.googleapis.com/upload/youtube/v3/videos?"):
                return 200, b"", {"Location": "https://www.googleapis.com/upload/youtube/v3/videos/session"}
            if request.full_url.endswith("/session") and request.get_method() == "PUT":
                body = request.data or b""
                put_requests.append((request.get_header("Content-range"), body))
                if len(put_requests) == 1:
                    return 308, b"", {"Range": "bytes=0-131071"}
                if len(put_requests) == 2:
                    return 308, b"", {"Range": "bytes=0-393215"}
                return 201, b'{"id":"video-123"}', {}
            self.fail("unexpected HTTP request: " + request.full_url)

        config = YouTubeConfig("id", "secret", "refresh", chunk_size=chunk_size)
        client = YouTubeClient(config, transport=transport)
        with tempfile.NamedTemporaryFile() as video:
            video.write(payload)
            video.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                result = client.upload_video(video.name, title="Test", description="Test",
                                             **self.publish_context())

        self.assertEqual(result["video_id"], "video-123")
        self.assertEqual(len(put_requests), 3)
        self.assertEqual(put_requests[0][1], payload[:chunk_size])
        self.assertEqual(put_requests[1][1], payload[131072:131072 + chunk_size])
        self.assertEqual(put_requests[2][1], payload[393216:])

    def test_resumable_upload_rejects_impossible_acknowledgement(self):
        chunk_size = 256 * 1024

        def transport(request, timeout):
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                return 200, b'{"access_token":"test-token"}', {}
            if request.full_url.startswith("https://www.googleapis.com/upload/youtube/v3/videos?"):
                return 200, b"", {"Location": "https://www.googleapis.com/upload/youtube/v3/videos/session"}
            if request.full_url.endswith("/session"):
                return 308, b"", {"Range": "bytes=0-999999"}
            self.fail("unexpected HTTP request")

        client = YouTubeClient(YouTubeConfig("id", "secret", "refresh", chunk_size=chunk_size),
                               transport=transport)
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"x" * chunk_size)
            video.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "impossible byte range"):
                    client.upload_video(video.name, title="Test", description="Test",
                                        **self.publish_context())

    def test_upload_requires_existing_nonempty_file(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with self.assertRaisesRegex(YouTubeIntegrationError, "missing or empty"):
            client.upload_video("/definitely/not/a/real/video.mp4", title="Approved",
                description="Test", **self.publish_context())


if __name__ == "__main__":
    unittest.main()
