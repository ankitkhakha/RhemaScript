"""Tests for the least-privilege YouTube OAuth bootstrap."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from rhemascript.integrations import oauth_readonly


class ReadOnlyOAuthBootstrapTests(unittest.TestCase):
    def test_pkce_pair_uses_s256(self):
        verifier, challenge = oauth_readonly._create_pkce_pair()
        import base64
        import hashlib

        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(challenge, expected)
        self.assertNotEqual(verifier, challenge)

    def test_accepts_exact_read_only_scope_and_refresh_token(self):
        access, refresh = oauth_readonly._validate_token_response({
            "scope": oauth_readonly.READ_ONLY_SCOPE,
            "access_token": "access-test",
            "refresh_token": "refresh-test",
            "token_type": "Bearer",
        })
        self.assertEqual(access, "access-test")
        self.assertEqual(refresh, "refresh-test")

    def test_rejects_upload_or_analytics_scope(self):
        for scope in (
            oauth_readonly.READ_ONLY_SCOPE + " https://www.googleapis.com/auth/youtube.upload",
            oauth_readonly.READ_ONLY_SCOPE + " https://www.googleapis.com/auth/yt-analytics.readonly",
            "https://www.googleapis.com/auth/youtube.upload",
        ):
            with self.subTest(scope=scope):
                with self.assertRaises(oauth_readonly.OAuthBootstrapError):
                    oauth_readonly._validate_token_response({
                        "scope": scope,
                        "access_token": "access-test",
                        "refresh_token": "refresh-test",
                        "token_type": "Bearer",
                    })

    def test_rejects_missing_scope_or_refresh_token(self):
        with self.assertRaises(oauth_readonly.OAuthBootstrapError):
            oauth_readonly._validate_token_response({
                "access_token": "access-test",
                "refresh_token": "refresh-test",
                "token_type": "Bearer",
            })
        with self.assertRaises(oauth_readonly.OAuthBootstrapError):
            oauth_readonly._validate_token_response({
                "scope": oauth_readonly.READ_ONLY_SCOPE,
                "access_token": "access-test",
                "token_type": "Bearer",
            })


    def test_callback_rejects_duplicate_state_and_unexpected_parameters(self):
        from http.client import HTTPConnection
        from threading import Thread

        for suffix in (
            "?state=expected-state&state=expected-state&code=test-code",
            "?state=expected-state&code=test-code&extra=not-allowed",
        ):
            with self.subTest(suffix=suffix):
                result = {}
                server = oauth_readonly.HTTPServer(
                    ("127.0.0.1", 0),
                    oauth_readonly._callback_handler(result, "expected-state"),
                )
                thread = Thread(target=server.handle_request, daemon=True)
                thread.start()
                connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                connection.request("GET", oauth_readonly.CALLBACK_PATH + suffix)
                response = connection.getresponse()
                response.read()
                connection.close()
                thread.join(timeout=3)
                server.server_close()
                self.assertEqual(response.status, 400)
                self.assertIn("error", result)

    def test_callback_accepts_one_valid_state_and_code_once(self):
        from http.client import HTTPConnection
        from threading import Thread

        result = {}
        server = oauth_readonly.HTTPServer(
            ("127.0.0.1", 0),
            oauth_readonly._callback_handler(result, "expected-state"),
        )
        thread = Thread(target=server.handle_request, daemon=True)
        thread.start()
        connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
        connection.request("GET", oauth_readonly.CALLBACK_PATH +
                           "?state=expected-state&code=single-use-code")
        response = connection.getresponse()
        response.read()
        connection.close()
        thread.join(timeout=3)
        server.server_close()
        self.assertEqual(response.status, 200)
        self.assertEqual(result.get("code"), "single-use-code")

    def test_rejects_invalid_timeout(self):
        with self.assertRaises(oauth_readonly.OAuthBootstrapError):
            oauth_readonly._receive_loopback_code(
                client_id="desktop-client-id", timeout_seconds=0
            )

    @patch("rhemascript.integrations.oauth_readonly.write_private_credentials")
    @patch("rhemascript.integrations.oauth_readonly._exchange_code")
    @patch("rhemascript.integrations.oauth_readonly._receive_loopback_code")
    def test_scope_mismatch_never_writes_credentials(
        self, receive, exchange, write_credentials
    ):
        receive.return_value = ("one-time-code", "pkce-verifier", "http://127.0.0.1/callback")
        exchange.return_value = {
            "scope": oauth_readonly.READ_ONLY_SCOPE
                    + " https://www.googleapis.com/auth/youtube.upload",
            "access_token": "access-test",
            "refresh_token": "refresh-test",
            "token_type": "Bearer",
        }
        with self.assertRaises(oauth_readonly.OAuthBootstrapError):
            oauth_readonly.run_bootstrap(
                client_id="desktop-client-id",
                client_secret="desktop-client-secret",
                credential_path="/private/youtube-oauth.json",
            )
        write_credentials.assert_not_called()

    @patch("rhemascript.integrations.oauth_readonly.write_private_credentials")
    @patch("rhemascript.integrations.oauth_readonly._exchange_code")
    @patch("rhemascript.integrations.oauth_readonly._receive_loopback_code")
    def test_exact_scope_saves_only_the_returned_refresh_token(
        self, receive, exchange, write_credentials
    ):
        receive.return_value = ("one-time-code", "pkce-verifier", "http://127.0.0.1/callback")
        exchange.return_value = {
            "scope": oauth_readonly.READ_ONLY_SCOPE,
            "access_token": "access-test",
            "refresh_token": "refresh-test",
            "token_type": "Bearer",
        }
        oauth_readonly.run_bootstrap(
            client_id="desktop-client-id",
            client_secret="desktop-client-secret",
            credential_path="/private/youtube-oauth.json",
        )
        write_credentials.assert_called_once_with(
            "/private/youtube-oauth.json",
            client_id="desktop-client-id",
            client_secret="desktop-client-secret",
            refresh_token="refresh-test",
        )


if __name__ == "__main__":
    unittest.main()
