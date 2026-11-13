import os
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from unittest.mock import patch
import hashlib
import json
import shutil
from pathlib import Path
from urllib.error import URLError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from rhemascript.core.approvals import ApprovalVerifier
from rhemascript.core.approval_store import SQLitePublishSessionRegistry

from rhemascript.interfaces.external import ExternalIntegrationGateway, UrllibTransport, ExternalIntegrationError
from rhemascript.integrations.youtube import (
    YOUTUBE_INTERFACE_ID, YouTubeClient, YouTubeConfig, YouTubeIntegrationError, youtube_provider_binding,
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
                raise AssertionError("undedicated signed thumbnail-artifact approval contractway operation")

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

    def publish_context(self, *, authorised=True, final_film_bytes=b'video', approval_store=None):
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
        evidence_root = tempfile.mkdtemp(prefix="rhemascript-final-film-test-")
        self.addCleanup(shutil.rmtree, evidence_root, ignore_errors=True)
        artifacts = []
        links = []
        previous = None
        final_artifact_bytes = None
        for index, kind in enumerate(kinds):
            ident = f"ART-{index + 1}"
            artifact_bytes = final_film_bytes if kind == "EDITED_FILM" else f"synthetic:{ident}".encode()
            local_path = f"{ident}.bin"
            with open(os.path.join(evidence_root, local_path), "wb") as artifact_file:
                artifact_file.write(artifact_bytes)
            artifact = {
                "artifact_id": ident, "project_id": "RS-TEST-001",
                "project_version": "1.0", "artifact_type": kind,
                "version": "1", "status": "APPROVED",
                "evidence_refs": ["evidence:FINAL_FILM"] if kind == "EDITED_FILM" else [],
                "local_path": local_path,
                "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            }
            artifacts.append(artifact)
            if kind == "EDITED_FILM":
                final_artifact_bytes = artifact_bytes
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
        now = datetime.now(timezone.utc)
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        consumed = set()

        def consume_once(entries):
            identities = [(item.approval_id, item.nonce) for item in entries]
            if len(set(identities)) != len(identities) or any(item in consumed for item in identities):
                return False
            consumed.update(identities)
            return True

        approval_verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=(approval_store.consume_many_once if approval_store is not None else consume_once),
            clock=lambda: now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {
                    "FINAL_ACCEPTANCE": ["director"],
                    "PUBLISH": ["publisher"],
                },
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )
        request_id = "publish-request-001"
        final_artifact = next(item for item in artifacts if item["artifact_type"] == "EDITED_FILM")
        artifact_binding = {
            "artifact_id": final_artifact["artifact_id"],
            "artifact_version": final_artifact["version"],
            "sha256": final_artifact["sha256"],
            "size_bytes": len(final_artifact_bytes),
        }

        def signed_credential(action, actor, suffix):
            payload = {
                "schema": "RhemaScript.ApprovalCredential.v3",
                "approval_id": f"approval-{suffix}",
                "issuer": "RhemaScript-Approval-Service",
                "actor_id": actor,
                "action": action,
                "project_id": "RS-TEST-001",
                "project_version": "1.0",
                "request_id": request_id,
                "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "nonce": f"nonce-{suffix}",
                "key_id": "key-2026-01",
                "artifact_id": artifact_binding["artifact_id"],
                "artifact_version": artifact_binding["artifact_version"],
                "artifact_sha256": artifact_binding["sha256"],
                "artifact_size_bytes": artifact_binding["size_bytes"],
                "subject_id": "subject-" + actor,
                "actor_role": "director" if action == "FINAL_ACCEPTANCE" else "publisher",
                "authn_context": "mfa",
                "authenticated_at": now.isoformat(),
                "identity_session_id": "session-" + actor,
                "identity_policy_version": "identity-policy-v1",
                "identity_provider_id": "test-idp",
            }
            payload["signature"] = private_key.sign(
                json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode()
            ).hex()
            return payload

        publisher_actor = "director-000" if authorised else "director-001"
        return {
            "evidence_pack": evidence_pack,
            "final_film_evidence_ref": "evidence:FINAL_FILM",
            "evidence_root": evidence_root,
            "approval_verifier": approval_verifier,
            "approval_credentials": (
                signed_credential("FINAL_ACCEPTANCE", "director-001", "final-001"),
                signed_credential("PUBLISH", publisher_actor, "publish-001"),
            ),
            "approval_request_id": request_id,
        }

    def add_verified_video_evidence(self, context, video_id="video-123"):
        verification_bytes = json.dumps({
            "youtube_video_id": video_id,
            "verified_final_film_artifact_id": "ART-8",
            "verification_method": "YOUTUBE_API_VIDEO_READ",
            "upload_status": "uploaded",
            "processing_status": "succeeded",
        }, sort_keys=True).encode()
        local_path = "YT-VERIFY-1.json"
        with open(os.path.join(context["evidence_root"], local_path), "wb") as stream:
            stream.write(verification_bytes)
        context["evidence_pack"]["artifacts"].append({
            "artifact_id": "YT-VERIFY-1",
            "project_id": "RS-TEST-001",
            "project_version": "1.0",
            "artifact_type": "YOUTUBE_VIDEO_VERIFICATION",
            "version": "1",
            "status": "VERIFIED",
            "local_path": local_path,
            "sha256": hashlib.sha256(verification_bytes).hexdigest(),
            "youtube_video_id": video_id,
            "verified_final_film_artifact_id": "ART-8",
            "verification_method": "YOUTUBE_API_VIDEO_READ",
            "upload_status": "uploaded",
            "processing_status": "succeeded",
        })
        return context

    def mark_client_as_read_back_verified(self, client, video_id="video-123"):
        # Test fixture for the private process-local trust anchor established
        # only by verify_video() after a successful API read-back.
        client._verified_upload_context = {
            "video_id": video_id,
            "project_id": "RS-TEST-001",
            "project_version": "1.0",
            "final_film_artifact_id": "ART-8",
        }


    def test_provider_gateway_rejects_boolean_publish_authority_before_transport(self):
        calls = []

        class RecordingTransport:
            def send_request(self, url, method, headers, body, timeout):
                calls.append((url, method))
                return 200, b"{}", {}

        gateway = ExternalIntegrationGateway(
            (youtube_provider_binding(),),
            transport=RecordingTransport(),
            credential_resolver=lambda provider: {},
            audit_sink=lambda event: None,
            enabled=True,
        )
        with self.assertRaisesRegex(ExternalIntegrationError, "verifier-issued signed approvals"):
            gateway.request(
                YOUTUBE_INTERFACE_ID, "UPLOAD_SESSION",
                "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable",
                method="POST", headers={}, body=b"{}",
                request_id="publish-request-001",
                project_id="RS-TEST-001", source_version="1.0",
                authority={"publishing_authorisation": True},
            )
        self.assertEqual(calls, [])

    def test_config_rejects_upload_chunk_larger_than_32_mib(self):
        with self.assertRaisesRegex(YouTubeIntegrationError, "between 256 KiB and 32 MiB"):
            YouTubeConfig("client", "secret", "refresh", chunk_size=33 * 1024 * 1024).validate()

    def test_config_rejects_non_aligned_upload_chunk(self):
        with self.assertRaisesRegex(YouTubeIntegrationError, "between 256 KiB and 32 MiB"):
            YouTubeConfig("client", "secret", "refresh", chunk_size=256 * 1024 + 1).validate()

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
        with tempfile.TemporaryDirectory() as registry_directory:
            os.chmod(registry_directory, 0o700)
            registry = SQLitePublishSessionRegistry(Path(registry_directory) / "approval.sqlite3")
            gateway = ExternalIntegrationGateway(
                (youtube_provider_binding(),), transport=transport,
                credential_resolver=lambda provider: {}, audit_sink=events.append,
                publish_session_registry=registry, enabled=True,
            )
            client = YouTubeClient(self.config(), gateway=gateway)
            with tempfile.NamedTemporaryFile() as video:
                video.write(b"approved-video-bytes")
                video.flush()
                with patch("rhemascript.core.authority.authorise_action", return_value=True):
                    result = client.upload_video(
                        video.name, title="Approved", description="Test",
                        **self.publish_context(
                            final_film_bytes=b"approved-video-bytes", approval_store=registry,
                        ),
                    )
                    calls_after_upload = len(transport.calls)
                    with self.assertRaisesRegex(ExternalIntegrationError, "already has a publish-session claim"):
                        gateway.request(
                            YOUTUBE_INTERFACE_ID, "UPLOAD_SESSION",
                            "https://www.googleapis.com/upload/youtube/v3/videos",
                            method="POST", headers={}, body=b"{}",
                            request_id="publish-request-001", project_id="RS-TEST-001",
                            source_version="1.0", authority=client._gateway_authority,
                        )
                    self.assertEqual(len(transport.calls), calls_after_upload)
                    verified = client.verify_video(result["video_id"])
            session = registry.get_publish_session(
                project_id="RS-TEST-001", project_version="1.0",
                request_id="publish-request-001",
            )
            self.assertEqual(session["state"], "COMPLETE")
            self.assertEqual(session["acknowledged_offset"], len(b"approved-video-bytes"))
            self.assertEqual(len(session["session_url_sha256"]), 64)
            self.assertNotIn(b"private-session", registry.path.read_bytes())

        self.assertEqual(result["video_id"], "gateway-video")
        self.assertTrue(result["upload_completed"])
        self.assertTrue(result["verification_required"])
        self.assertNotIn("upload_verified", result)
        self.assertEqual(verified["privacy_status"], "private")
        self.assertEqual(verified["verification_evidence"]["youtube_video_id"], "gateway-video")
        self.assertEqual(
            verified["verification_evidence"]["verified_final_film_artifact_id"], "ART-8"
        )
        self.assertEqual([call[1] for call in transport.calls],
                         ["POST", "POST", "PUT", "GET"])
        self.assertEqual(
            [event["operation"] for event in events if event["phase"] == "REQUESTED"],
            ["OAUTH_TOKEN", "UPLOAD_SESSION", "UPLOAD_CHUNK", "VIDEO_READ"],
        )
        self.assertNotIn("gateway-access", repr(events))
        self.assertNotIn("private-session", repr(events))
        self.assertNotIn("approved-video-bytes", repr(events))

    def test_upload_session_is_denied_before_provider_write_without_durable_registry(self):
        class MethodTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append(url)
                self.fail("no network request is allowed without the durable registry")
        transport = MethodTransport()
        client = YouTubeClient(self.config(), gateway=ExternalIntegrationGateway(
            (youtube_provider_binding(),), transport=transport,
            credential_resolver=lambda provider: {}, audit_sink=lambda event: None, enabled=True,
        ))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"approved-video-bytes")
            video.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "durable SQLite publish-session registry"):
                    client.upload_video(
                        video.name, title="Approved", description="Test",
                        **self.publish_context(final_film_bytes=b"approved-video-bytes"),
                    )
        self.assertEqual(transport.calls, [])

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

    def test_thumbnail_write_is_blocked_without_thumbnail_specific_signed_approval(self):
        class NeverThumbnailTransport:
            def __init__(self):
                self.calls = []
            def send_request(self, url, method, headers, body, timeout):
                self.calls.append((url, method, body))
                raise AssertionError("thumbnail provider request must not be sent")

        transport = NeverThumbnailTransport()
        gateway = ExternalIntegrationGateway(
            (youtube_provider_binding(),), transport=transport,
            credential_resolver=lambda provider: {}, audit_sink=lambda event: None, enabled=True,
        )
        client = YouTubeClient(self.config(), gateway=gateway)
        with tempfile.NamedTemporaryFile(suffix=".png") as image:
            image.write(b"thumbnail-bytes")
            image.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
                client.set_thumbnail(
                    "video-123", image.name, **self.add_verified_video_evidence(self.publish_context()),
                )
        self.assertEqual(transport.calls, [])

    def test_thumbnail_write_remains_disabled_without_project_verification_evidence(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.publish_context()
        with tempfile.NamedTemporaryFile(suffix=".png") as image:
            image.write(b"thumbnail")
            image.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
                    client.set_thumbnail("video-123", image.name, **context)

    def test_thumbnail_write_remains_disabled_for_caller_fabricated_verification(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.add_verified_video_evidence(self.publish_context())
        with tempfile.NamedTemporaryFile(suffix=".png") as image:
            image.write(b"thumbnail")
            image.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
                    client.set_thumbnail("video-123", image.name, **context)

    def test_thumbnail_write_remains_disabled_for_mismatched_final_film(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.add_verified_video_evidence(self.publish_context())
        context["evidence_pack"]["artifacts"][-1]["verified_final_film_artifact_id"] = "ART-7"
        with tempfile.NamedTemporaryFile(suffix=".png") as image:
            image.write(b"thumbnail")
            image.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
                    client.set_thumbnail("video-123", image.name, **context)

    def test_thumbnail_write_remains_disabled_for_oversized_file(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        self.mark_client_as_read_back_verified(client)
        with tempfile.NamedTemporaryFile(suffix=".png") as image:
            image.write(b"x" * (2 * 1024 * 1024 + 1))
            image.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
                    client.set_thumbnail("video-123", image.name, **self.add_verified_video_evidence(self.publish_context()))

    def test_thumbnail_write_remains_disabled_for_unknown_extension(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        self.mark_client_as_read_back_verified(client)
        with tempfile.NamedTemporaryFile(suffix=".gif") as image:
            image.write(b"image")
            image.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaisesRegex(YouTubeIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
                    client.set_thumbnail("video-123", image.name, **self.add_verified_video_evidence(self.publish_context()))

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
            with self.assertRaisesRegex(YouTubeIntegrationError, "distinct authenticated actors"):
                client.upload_video(video.name, title="Approved", description="Test",
                                    **self.publish_context(authorised=False))

    def test_thumbnail_write_remains_disabled_without_project_authority(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.publish_context(authorised=False)
        with self.assertRaisesRegex(YouTubeIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
            client.set_thumbnail("video-123", "/not/read.png", **context)

    def test_final_gate_must_reference_the_approved_final_film(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.publish_context()
        context["evidence_pack"]["gate_records"][-1]["evidence_ref"] = "evidence:OTHER-FILM"
        with self.assertRaisesRegex(YouTubeIntegrationError, "does not match the approved final film"):
            client.upload_video("/not/read.mp4", title="Approved", description="Test", **context)

    def test_thumbnail_write_remains_disabled_for_out_of_order_gate_records(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        context = self.publish_context()
        context["evidence_pack"]["gate_records"][0], context["evidence_pack"]["gate_records"][1] = (
            context["evidence_pack"]["gate_records"][1],
            context["evidence_pack"]["gate_records"][0],
        )
        with self.assertRaisesRegex(YouTubeIntegrationError, "dedicated signed thumbnail-artifact approval contract"):
            client.set_thumbnail("video-123", "/not/read.png", **context)

    def test_invalid_video_metadata_is_rejected_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "1 to 100"):
                client.upload_video(video.name, title="", description="Test",
                                    **self.publish_context())

    def test_scheduled_publication_timestamp_requires_timezone_and_future_time(self):
        from datetime import datetime, timezone
        from rhemascript.integrations.youtube import _validate_publish_at
        now = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
        for invalid in (
            "2026-11-12T13:00:00",
            "2026-02-30T13:00:00Z",
            "2026-11-12T11:59:59Z",
            "2026-11-12T12:00:00Z",
            "not-a-date",
        ):
            with self.subTest(value=invalid):
                with self.assertRaises(YouTubeIntegrationError):
                    _validate_publish_at(invalid, now=now)
        self.assertEqual(
            _validate_publish_at("2026-11-12T18:00:00+05:30", now=now),
            "2026-11-12T18:00:00+05:30",
        )

    def test_invalid_final_film_evidence_is_rejected_before_upload_network(self):
        calls = []
        client = YouTubeClient(self.config(), transport=lambda *args: calls.append(args))
        context = self.publish_context()
        for item in context["evidence_pack"]["artifacts"]:
            if item["artifact_type"] == "EDITED_FILM":
                item["status"] = "DRAFT"
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "final film"):
                client.upload_video(
                    video.name, title="Approved", description="Test", **context,
                )
        self.assertEqual(calls, [])

    def test_invalid_scheduled_timestamp_is_rejected_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            for invalid in ("2026-12-01T12:00:00", "2020-01-01T00:00:00Z"):
                with self.subTest(value=invalid):
                    with self.assertRaises(YouTubeIntegrationError):
                        client.upload_video(
                            video.name, title="Approved", description="Test",
                            publish_at=invalid, **self.publish_context(),
                        )

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

    def test_upload_rejects_invalid_tags_and_category_before_network(self):
        client = YouTubeClient(
            self.config(),
            transport=lambda *args: self.fail("network must not be called"),
        )
        invalid_options = (
            {"tags": ["valid", ""]},
            {"tags": ["   "]},
            {"tags": [1]},
            {"tags": ["x" * 501]},
            {"category_id": True},
            {"category_id": "not-numeric"},
            {"category_id": 22.5},
        )
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            for options in invalid_options:
                with self.subTest(options=options):
                    with self.assertRaises(YouTubeIntegrationError):
                        client.upload_video(
                            video.name, title="Approved", description="Test",
                            **self.publish_context(), **options,
                        )

    def test_analytics_rejects_datetime_and_malformed_parameters_before_network(self):
        client = YouTubeClient(
            self.config(),
            transport=lambda *args: self.fail("network must not be called"),
        )
        valid = date(2026, 11, 1)
        invalid_calls = (
            {"start_date": datetime(2026, 11, 1), "end_date": valid},
            {"start_date": valid, "end_date": datetime(2026, 11, 2)},
            {"start_date": valid, "end_date": valid, "metrics": ""},
            {"start_date": valid, "end_date": valid, "metrics": "x" * 501},
            {"start_date": valid, "end_date": valid, "dimensions": " "},
            {"start_date": valid, "end_date": valid, "dimensions": "x" * 201},
            {"start_date": valid, "end_date": valid, "filters": 42},
            {"start_date": valid, "end_date": valid, "filters": "x" * 501},
        )
        for kwargs in invalid_calls:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(YouTubeIntegrationError):
                    client.analytics(**kwargs)

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
                                             **self.publish_context(final_film_bytes=payload))

        self.assertEqual(result["video_id"], "video-123")
        self.assertEqual(len(put_requests), 3)
        self.assertEqual(put_requests[0][1], payload[:chunk_size])
        self.assertEqual(put_requests[1][1], payload[131072:131072 + chunk_size])
        self.assertEqual(put_requests[2][1], payload[393216:])

    def test_indeterminate_chunk_write_reconciles_existing_session_before_resuming(self):
        chunk_size = 256 * 1024
        payload = bytes((i % 251 for i in range(chunk_size + 64)))
        put_ranges = []
        simulated_received = 0
        status_queries = 0

        def transport(request, timeout):
            nonlocal simulated_received, status_queries
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                return 200, b'{"access_token":"test-token"}', {}
            if request.full_url.startswith("https://www.googleapis.com/upload/youtube/v3/videos?"):
                return 200, b"", {"Location":"https://www.googleapis.com/upload/youtube/v3/videos/session"}
            if request.full_url.endswith("/session") and request.get_method() == "PUT":
                content_range = request.get_header("Content-range")
                if content_range == f"bytes */{len(payload)}":
                    status_queries += 1
                    if simulated_received:
                        return 308, b"", {"Range":f"bytes=0-{simulated_received - 1}"}
                    return 308, b"", {}
                put_ranges.append(content_range)
                body = request.data or b""
                if len(put_ranges) == 1:
                    # Provider accepted part of the first chunk, then the response was lost.
                    simulated_received = 131072
                    raise URLError("simulated lost response after provider accepted bytes")
                self.assertEqual(content_range, f"bytes {simulated_received}-{len(payload)-1}/{len(payload)}")
                self.assertEqual(body, payload[simulated_received:])
                simulated_received = len(payload)
                return 201, b'{"id":"video-reconciled"}', {}
            self.fail("unexpected HTTP request: " + request.full_url)

        client = YouTubeClient(YouTubeConfig("id", "secret", "refresh", chunk_size=chunk_size),
                               transport=transport)
        with tempfile.NamedTemporaryFile() as video:
            video.write(payload)
            video.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                result = client.upload_video(video.name, title="Test", description="Test",
                                             **self.publish_context(final_film_bytes=payload))
        self.assertEqual(result["video_id"], "video-reconciled")
        self.assertEqual(status_queries, 1)
        self.assertEqual(len(put_ranges), 2)
        self.assertEqual(put_ranges[1], f"bytes 131072-{len(payload)-1}/{len(payload)}")

    def test_indeterminate_upload_session_creation_is_not_replayed(self):
        calls = []

        def transport(request, timeout):
            calls.append(request.get_method())
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                return 200, b'{"access_token":"test-token"}', {}
            if request.full_url.startswith("https://www.googleapis.com/upload/youtube/v3/videos?"):
                raise URLError("simulated lost session-creation response")
            self.fail("no request may follow an indeterminate session creation")

        client = YouTubeClient(self.config(), transport=transport)
        context = self.publish_context()
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaises(YouTubeIntegrationError) as caught:
                    client.upload_video(video.name, title="Test", description="Test", **context)
        self.assertEqual(caught.exception.code, "INDETERMINATE_WRITE")
        self.assertIn("before retrying", str(caught.exception))
        self.assertEqual(calls, ["POST", "POST"])

    def test_provider_5xx_during_session_creation_is_indeterminate(self):
        calls = []

        def transport(request, timeout):
            calls.append(request.get_method())
            if request.full_url.startswith("https://oauth2.googleapis.com/token"):
                return 200, b'{"access_token":"test-token"}', {}
            if request.full_url.startswith("https://www.googleapis.com/upload/youtube/v3/videos?"):
                return 503, b'{"error":"temporarily unavailable"}', {}
            self.fail("indeterminate session creation must not be retried")

        client = YouTubeClient(self.config(), transport=transport)
        context = self.publish_context()
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with patch("rhemascript.core.authority.authorise_action", return_value=True):
                with self.assertRaises(YouTubeIntegrationError) as caught:
                    client.upload_video(video.name, title="Test", description="Test", **context)
        self.assertEqual(caught.exception.code, "INDETERMINATE_WRITE")
        self.assertEqual(calls, ["POST", "POST"])

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
                                        **self.publish_context(final_film_bytes=b"x" * chunk_size))


    def test_publish_rejects_changed_final_film_bytes_before_provider_network(self):
        calls = []
        context = self.publish_context()
        final_artifact = next(
            item for item in context["evidence_pack"]["artifacts"]
            if item["artifact_type"] == "EDITED_FILM"
        )
        with open(os.path.join(context["evidence_root"], final_artifact["local_path"]), "wb") as stream:
            stream.write(b"tampered-final-film")
        client = YouTubeClient(self.config(), transport=lambda *args: calls.append(args))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "content does not match declared SHA-256"):
                client.upload_video(video.name, title="Approved", description="Test", **context)
        self.assertEqual(calls, [])

    def test_publish_rejects_upload_file_not_matching_signed_final_film(self):
        calls = []
        context = self.publish_context(final_film_bytes=b"approved-final-film")
        client = YouTubeClient(self.config(), transport=lambda *args: calls.append(args))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"different-upload-bytes")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "do not match the signed final-film artifact digest"):
                client.upload_video(video.name, title="Approved", description="Test", **context)
        self.assertEqual(calls, [])

    def test_publish_rejects_one_approval_with_different_final_film_digest(self):
        calls = []
        context = self.publish_context()
        token = context["approval_credentials"][1]
        token["artifact_sha256"] = "b" * 64
        payload = {key: value for key, value in token.items() if key != "signature"}
        token["signature"] = self._sign_test_approval(context, payload)
        client = YouTubeClient(self.config(), transport=lambda *args: calls.append(args))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "binding does not match verified bytes"):
                client.upload_video(video.name, title="Approved", description="Test", **context)
        self.assertEqual(calls, [])

    def _sign_test_approval(self, context, payload):
        # The fixture deliberately keeps its private key out of the production API.
        # This helper re-signs a deliberately altered test credential for a valid
        # signature over the wrong artifact digest.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        return key.sign(
            json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode()
        ).hex()

    def test_upload_requires_existing_nonempty_file(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with self.assertRaisesRegex(YouTubeIntegrationError, "missing or cannot be opened safely"):
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
