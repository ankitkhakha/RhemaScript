"""Tests for the least-privilege YouTube OAuth bootstrap."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from rhemascript.integrations import oauth_readonly


class ReadOnlyOAuthBootstrapTests(unittest.TestCase):
    def test_callback_diagnostics_expose_only_safe_categories(self):
        self.assertEqual(
            oauth_readonly._safe_callback_error_category("state_mismatch"),
            "state_mismatch",
        )
        self.assertEqual(
            oauth_readonly._safe_callback_error_category("unexpected_parameters"),
            "unexpected_parameters",
        )
        self.assertEqual(
            oauth_readonly._safe_callback_error_category("authorization_code_secret"),
            "callback_rejected",
        )

    @patch("rhemascript.integrations.oauth_readonly.build_opener")
    def test_token_exchange_reports_only_allowlisted_google_error_code(self, build_opener):
        from urllib.error import HTTPError
        from io import BytesIO

        build_opener.return_value.open.side_effect = HTTPError(
            oauth_readonly.TOKEN_URL,
            400,
            "Bad Request",
            {},
            BytesIO(b'{"error":"invalid_client","error_description":"DO_NOT_EXPOSE_SECRET"}'),
        )
        with self.assertRaisesRegex(
            oauth_readonly.OAuthBootstrapError,
            r"HTTP 400, invalid_client.*no credentials were saved",
        ) as caught:
            oauth_readonly._exchange_code(
                client_id="client-id", client_secret="test-client-secret",
                code="one-time-code", redirect_uri="http://127.0.0.1/callback",
                verifier="pkce-verifier",
            )
        self.assertNotIn("DO_NOT_EXPOSE_SECRET", str(caught.exception))

    def test_google_error_descriptions_are_mapped_to_fixed_safe_categories(self):
        self.assertEqual(
            oauth_readonly._safe_google_error_detail(
                "Missing required parameter: code_verifier"
            ),
            "missing_code_verifier",
        )
        self.assertEqual(
            oauth_readonly._safe_google_error_detail("Invalid code verifier."),
            "invalid_code_verifier",
        )
        self.assertEqual(
            oauth_readonly._safe_google_error_detail("client_secret is missing."),
            "missing_client_secret",
        )
        self.assertIsNone(
            oauth_readonly._safe_google_error_detail("DO_NOT_EXPOSE_SECRET")
        )

    @patch("rhemascript.integrations.oauth_readonly.build_opener")
    def test_token_exchange_includes_only_allowlisted_error_detail(self, build_opener):
        from urllib.error import HTTPError
        from io import BytesIO

        build_opener.return_value.open.side_effect = HTTPError(
            oauth_readonly.TOKEN_URL,
            400,
            "Bad Request",
            {},
            BytesIO(
                b'{"error":"invalid_request",'
                b'"error_description":"Missing required parameter: code_verifier"}'
            ),
        )
        with self.assertRaisesRegex(
            oauth_readonly.OAuthBootstrapError,
            r"HTTP 400, invalid_request:missing_code_verifier",
        ):
            oauth_readonly._exchange_code(
                client_id="client-id", client_secret="test-client-secret",
                code="one-time-code", redirect_uri="http://127.0.0.1",
                verifier="pkce-verifier",
            )

    @patch("rhemascript.integrations.oauth_readonly.build_opener")
    def test_token_exchange_sends_client_secret_only_in_post_body(self, build_opener):
        from io import BytesIO
        from unittest.mock import MagicMock
        from urllib.parse import parse_qs

        response = MagicMock()
        response.status = 200
        response.read.return_value = (
            b'{"scope":"' + oauth_readonly.READ_ONLY_SCOPE.encode("ascii")
            + b'","access_token":"access-test","refresh_token":"refresh-test",'
            b'"token_type":"Bearer"}'
        )
        response.__enter__.return_value = response
        build_opener.return_value.open.return_value = response

        oauth_readonly._exchange_code(
            client_id="desktop-client-id",
            client_secret="test-client-secret",
            code="one-time-code",
            redirect_uri="http://127.0.0.1:12345",
            verifier="pkce-verifier",
        )

        request = build_opener.return_value.open.call_args.args[0]
        form = parse_qs(request.data.decode("ascii"))
        self.assertEqual(form["client_secret"], ["test-client-secret"])
        self.assertNotIn("test-client-secret", request.full_url)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Content-type"), "application/x-www-form-urlencoded")

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

    def test_callback_accepts_google_issuer_and_rejects_untrusted_issuer(self):
        from http.client import HTTPConnection
        from threading import Thread

        for issuer, expected_status in (
            ("https://accounts.google.com", 200),
            ("https://attacker.example", 400),
        ):
            with self.subTest(issuer=issuer):
                result = {}
                server = oauth_readonly.HTTPServer(
                    ("127.0.0.1", 0),
                    oauth_readonly._callback_handler(result, "expected-state"),
                )
                thread = Thread(target=server.handle_request, daemon=True)
                thread.start()
                connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                connection.request(
                    "GET",
                    oauth_readonly.CALLBACK_PATH
                    + "?state=expected-state&code=test-code&iss="
                    + issuer.replace(":", "%3A").replace("/", "%2F"),
                )
                response = connection.getresponse()
                response.read()
                connection.close()
                thread.join(timeout=3)
                server.server_close()
                self.assertEqual(response.status, expected_status)
                if expected_status == 200:
                    self.assertEqual(result.get("code"), "test-code")
                else:
                    self.assertIn("error", result)

    def test_callback_accepts_google_context_and_enforces_returned_scope(self):
        from http.client import HTTPConnection
        from threading import Thread

        cases = (
            (
                "?state=expected-state&code=test-code"
                "&iss=https%3A%2F%2Faccounts.google.com"
                "&scope=" + oauth_readonly.READ_ONLY_SCOPE.replace(":", "%3A").replace("/", "%2F")
                + "&authuser=0&prompt=consent",
                200,
            ),
            (
                "?state=expected-state&code=test-code&scope="
                "https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fyoutube.upload",
                400,
            ),
        )
        for suffix, expected_status in cases:
            with self.subTest(expected_status=expected_status):
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
                self.assertEqual(response.status, expected_status)
                if expected_status == 200:
                    self.assertEqual(result.get("code"), "test-code")
                else:
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
                client_id="desktop-client-id", client_secret="test-client-secret",
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
            client_id="desktop-client-id", client_secret="test-client-secret",
            credential_path="/private/youtube-oauth.json",
        )
        write_credentials.assert_called_once_with(
            "/private/youtube-oauth.json",
            client_id="desktop-client-id",
            refresh_token="refresh-test",
        )


if __name__ == "__main__":
    unittest.main()
