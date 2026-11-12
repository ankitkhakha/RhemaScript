import os
import tempfile
import unittest
from datetime import date
from unittest.mock import patch

from rhemascript.interfaces.external import ExternalIntegrationGateway, UrllibTransport
from rhemascript.integrations.youtube import (
    YOUTUBE_INTERFACE_ID, YouTubeClient, YouTubeConfig, YouTubeIntegrationError,
    youtube_provider_binding,
)


class YouTubeIntegrationTests(unittest.TestCase):
    def test_youtube_uses_dedicated_external_interface_18(self):
        self.assertEqual(YOUTUBE_INTERFACE_ID, "IF-18")

    def test_provider_binding_declares_if18_google_protocol_allowlist(self):
        binding = youtube_provider_binding()
        self.assertEqual(binding.interface_id, "IF-18")
        self.assertEqual(binding.provider_name, "youtube")
        self.assertEqual(binding.operations["OAUTH_TOKEN"]["method"], "POST")
        self.assertEqual(binding.operations["UPLOAD_CHUNK"]["method"], "PUT")
        self.assertIn("youtubeanalytics.googleapis.com",
                      binding.operations["ANALYTICS_READ"]["hosts"])

    def test_client_routes_oauth_and_channel_reads_through_gateway(self):
        class Gateway:
            def __init__(self):
                self.calls = []
            def request(self, interface_id, operation, url, **kwargs):
                self.calls.append((interface_id, operation, url, kwargs))
                if operation == "OAUTH_TOKEN":
                    return 200, b'{"access_token":"gateway-token"}', {}
                if operation == "CHANNEL_READ":
                    if kwargs["headers"].get("Authorization") != "Bearer gateway-token":
                        raise AssertionError("missing gateway access token")
                    return 200, b'{"items":[{"id":"channel-gateway"}]}', {}
                raise AssertionError("unexpected gateway operation")

        gateway = Gateway()
        client = YouTubeClient(self.config(), gateway=gateway,
                               project_id="RS-GATEWAY-TEST", source_version="2.0")
        result = client.channel()
        self.assertEqual(result["id"], "channel-gateway")
        self.assertEqual([call[0:2] for call in gateway.calls],
                         [("IF-18", "OAUTH_TOKEN"), ("IF-18", "CHANNEL_READ")])
        self.assertEqual(gateway.calls[0][3]["project_id"], "RS-GATEWAY-TEST")
        self.assertEqual(gateway.calls[0][3]["source_version"], "2.0")

    def test_read_only_connection_verifies_expected_channel_through_if18(self):
        class Gateway:
            def __init__(self):
                self.calls = []
            def request(self, interface_id, operation, url, **kwargs):
                self.calls.append((interface_id, operation, url, kwargs))
                if operation == "OAUTH_TOKEN":
                    return 200, b'{"access_token":"read-only-token"}', {}
                if operation == "CHANNEL_READ":
                    self.assert_authorization(kwargs)
                    if "part=snippet" not in url or "mine=true" not in url:
                        raise AssertionError("channel identity request must use the read-only snippet query")
                    return 200, b'{"items":[{"id":"UC-EXPECTED","snippet":{"title":"RhemaScript"}}]}', {}
                raise AssertionError("read-only verification attempted an unexpected operation")
            def assert_authorization(self, kwargs):
                if kwargs["headers"].get("Authorization") != "Bearer read-only-token":
                    raise AssertionError("missing OAuth bearer token")

        gateway = Gateway()
        client = YouTubeClient(self.config(), gateway=gateway)
        result = client.verify_connection(expected_channel_id="UC-EXPECTED")
        self.assertEqual(result, {
            "authenticated": True,
            "channel_id": "UC-EXPECTED",
            "channel_title": "RhemaScript",
            "read_only": True,
        })
        self.assertEqual(
            [call[0:2] for call in gateway.calls],
            [("IF-18", "OAUTH_TOKEN"), ("IF-18", "CHANNEL_READ")],
        )

    def test_read_only_connection_rejects_wrong_channel_identity(self):
        calls = []
        def transport(request, timeout):
            calls.append(request.get_method())
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                return 200, b'{"access_token":"read-only-token"}', {}
            return 200, b'{"items":[{"id":"UC-WRONG","snippet":{"title":"Other channel"}}]}', {}
        client = YouTubeClient(self.config(), transport=transport)
        with self.assertRaisesRegex(YouTubeIntegrationError, "does not match the expected channel ID"):
            client.verify_connection(expected_channel_id="UC-EXPECTED")
        self.assertEqual(calls, ["POST", "GET"])

    def test_read_only_connection_requires_expected_channel_id_before_network(self):
        calls = []
        client = YouTubeClient(self.config(), transport=lambda *args: calls.append(args))
        for value in ("", " UC-EXPECTED", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(YouTubeIntegrationError, "expected_channel_id"):
                    client.verify_connection(expected_channel_id=value)
        self.assertEqual(calls, [])

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

    def test_resumable_upload_and_verification_use_configured_if18_gateway(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, dict(headers), body))
                if url.startswith("https://oauth2.googleapis.com/token"):
                    return 200, b'{"access_token":"gateway-access"}', {}
                if url.startswith("https://www.googleapis.com/upload/youtube/v3/videos?"):
                    return 200, b"", {
                        "Location": "https://www.googleapis.com/upload/youtube/v3/videos/session?upload_id=private-session"
                    }
                if url.endswith("/session?upload_id=private-session") and method == "PUT":
                    return 201, b'{"id":"gateway-video"}', {}
                if url.startswith("https://www.googleapis.com/youtube/v3/videos?"):
                    return 200, b'{"items":[{"id":"gateway-video","snippet":{"title":"Approved"},"status":{"privacyStatus":"private","uploadStatus":"uploaded"},"processingDetails":{"processingStatus":"succeeded"}}]}', {}
                raise AssertionError("unexpected method-aware gateway request: " + method + " " + url)

        events = []
        transport = MethodTransport()
        gateway = ExternalIntegrationGateway(
            (youtube_provider_binding(),), transport=transport,
            credential_resolver=lambda provider: {}, audit_sink=events.append, enabled=True,
        )
        client = YouTubeClient(self.config(), gateway=gateway)
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"approved-video-bytes")
            video.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                result = client.upload_video(
                    video.name, title="Approved", description="Test",
                    **self.publish_context(),
                )
                verified = client.verify_video(result["video_id"])

        self.assertEqual(result["video_id"], "gateway-video")
        self.assertTrue(result["upload_completed"])
        self.assertTrue(result["verification_required"])
        self.assertNotIn("upload_verified", result)
        self.assertEqual(verified["privacy_status"], "private")
        self.assertEqual([call[1] for call in transport.calls],
                         ["POST", "POST", "PUT", "GET"])
        self.assertEqual(
            [event["operation"] for event in events if event["phase"] == "REQUESTED"],
            ["OAUTH_TOKEN", "UPLOAD_SESSION", "UPLOAD_CHUNK", "VIDEO_READ"],
        )
        self.assertNotIn("gateway-access", repr(events))
        self.assertNotIn("private-session", repr(events))
        self.assertNotIn("approved-video-bytes", repr(events))

    def test_verify_video_rejects_different_returned_video_id(self):
        def transport(request, timeout):
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                return 200, b'{"access_token":"verify-token"}', {}
            return 200, b'{"items":[{"id":"different-video","snippet":{"title":"Wrong"},"status":{"privacyStatus":"private"},"processingDetails":{"processingStatus":"succeeded"}}]}', {}
        client = YouTubeClient(self.config(), transport=transport)
        with self.assertRaisesRegex(YouTubeIntegrationError, "different video ID"):
            client.verify_video("expected-video")

    def test_verify_video_rejects_incomplete_status_objects(self):
        def transport(request, timeout):
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                return 200, b'{"access_token":"verify-token"}', {}
            return 200, b'{"items":[{"id":"expected-video","snippet":{},"status":null,"processingDetails":{}}]}', {}
        client = YouTubeClient(self.config(), transport=transport)
        with self.assertRaisesRegex(YouTubeIntegrationError, "incomplete video verification"):
            client.verify_video("expected-video")

    def test_verify_video_rejects_empty_video_id_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with self.assertRaisesRegex(YouTubeIntegrationError, "non-empty exact ID"):
            client.verify_video(" ")

    def test_thumbnail_write_uses_if18_gateway_and_publish_authority(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, dict(headers), body))
                if url.startswith("https://oauth2.googleapis.com/token"):
                    return 200, b'{"access_token":"thumb-access"}', {}
                if url.startswith("https://www.googleapis.com/upload/youtube/v3/thumbnails/set"):
                    return 200, b'{"items":[{"default":{"url":"thumbnail"}}]}', {}
                raise AssertionError("unexpected gateway request")

        events = []
        transport = MethodTransport()
        gateway = ExternalIntegrationGateway(
            (youtube_provider_binding(),), transport=transport,
            credential_resolver=lambda provider: {}, audit_sink=events.append, enabled=True,
        )
        client = YouTubeClient(self.config(), gateway=gateway)
        with tempfile.NamedTemporaryFile(suffix=".png") as image:
            image.write(b"thumbnail-bytes")
            image.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                result = client.set_thumbnail(
                    "video-123", image.name, **self.publish_context(),
                )

        self.assertIn("items", result)
        self.assertEqual([call[1] for call in transport.calls], ["POST", "POST"])
        self.assertEqual(
            [event["operation"] for event in events if event["phase"] == "REQUESTED"],
            ["OAUTH_TOKEN", "THUMBNAIL_WRITE"],
        )
        self.assertNotIn("thumb-access", repr(events))
        self.assertNotIn("thumbnail-bytes", repr(events))

    def test_thumbnail_rejects_oversized_file_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile(suffix=".png") as image:
            image.write(b"x" * (2 * 1024 * 1024 + 1))
            image.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "no larger than 2 MB"):
                    client.set_thumbnail("video-123", image.name, **self.publish_context())

    def test_thumbnail_rejects_unknown_extension_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile(suffix=".gif") as image:
            image.write(b"image")
            image.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "PNG or JPEG"):
                    client.set_thumbnail("video-123", image.name, **self.publish_context())

    def test_request_rejects_non_google_hosts_before_transport(self):
        calls = []
        client = YouTubeClient(self.config(), transport=lambda *args: calls.append(args))
        with self.assertRaisesRegex(YouTubeIntegrationError, "official HTTPS Google host allowlist"):
            client._request("https://attacker.example/collect", method="POST", body=b"secret")
        self.assertEqual(calls, [])

    def test_request_rejects_nonstandard_google_port_before_transport(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("transport must not run"))
        with self.assertRaisesRegex(YouTubeIntegrationError, "official HTTPS Google host allowlist"):
            client._request("https://www.googleapis.com:8443/youtube/v3/channels")

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

    def test_unauthorized_write_is_not_replayed_after_token_refresh(self):
        calls = []
        def transport(request, timeout):
            calls.append((request.get_method(), request.full_url))
            return 401, b'{"error":"unauthorized"}', {}

        client = YouTubeClient(self.config(), transport=transport)
        status, raw, _ = client._authorized_request(
            "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable",
            method="POST",
            body=b'{"snippet":{"title":"test"}}',
            headers={"Authorization": "Bearer expired-token"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(raw, b'{"error":"unauthorized"}')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "POST")


if __name__ == "__main__":
    unittest.main()
