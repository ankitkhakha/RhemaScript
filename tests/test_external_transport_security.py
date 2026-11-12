import unittest
from unittest.mock import patch

from rhemascript.interfaces.external import _NoRedirect, UrllibTransport


class ExternalTransportSecurityTests(unittest.TestCase):
    def test_redirect_handler_rejects_redirects(self):
        handler = _NoRedirect()
        result = handler.redirect_request(
            req=None, fp=None, code=302, msg="Found",
            headers={}, newurl="https://attacker.example/collect",
        )
        self.assertIsNone(result)

    def test_transport_installs_redirect_rejection_handler(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b'{"ok":true}'

        class Opener:
            def open(self, request, timeout):
                return Response()

        with patch(
            "rhemascript.interfaces.external.build_opener",
            return_value=Opener(),
        ) as build:
            status, body = UrllibTransport().send(
                "https://provider.example/api",
                {"Authorization": "Bearer never-log-this"},
                b'{"operation":"READ"}',
                5,
            )

        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"ok":true}')
        self.assertEqual(len(build.call_args.args), 1)
        self.assertIsInstance(build.call_args.args[0], _NoRedirect)


if __name__ == "__main__":
    unittest.main()
