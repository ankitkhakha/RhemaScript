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

    def test_missing_credentials_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(YouTubeIntegrationError):
                YouTubeConfig.from_environment()

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
            with self.assertRaisesRegex(YouTubeIntegrationError, "publishing authorisation"):
                client.upload_video(video.name, title="Approved", description="Test")

    def test_invalid_video_metadata_is_rejected_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "1 to 100"):
                client.upload_video(video.name, title="", description="Test",
                                    publishing_authorisation=True)

    def test_scheduled_publication_must_use_private_upload(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with tempfile.NamedTemporaryFile() as video:
            video.write(b"video")
            video.flush()
            with self.assertRaisesRegex(YouTubeIntegrationError, "requires private privacy"):
                client.upload_video(video.name, title="Approved", description="Test",
                    privacy_status="public", publish_at="2026-12-01T12:00:00Z",
                    publishing_authorisation=True)

    def test_analytics_date_range_is_validated_before_network(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with self.assertRaisesRegex(YouTubeIntegrationError, "cannot precede"):
            client.analytics(start_date=date(2026, 12, 2), end_date=date(2026, 12, 1))

    def test_upload_requires_existing_nonempty_file(self):
        client = YouTubeClient(self.config(), transport=lambda *args: self.fail("network must not be called"))
        with self.assertRaisesRegex(YouTubeIntegrationError, "missing or empty"):
            client.upload_video("/definitely/not/a/real/video.mp4", title="Approved",
                description="Test", publishing_authorisation=True)


if __name__ == "__main__":
    unittest.main()
