import unittest

from raei.outbound_security import (
    OutboundRequestError, validate_outbound_url, validate_upstream_json,
)


class OutboundUrlTests(unittest.TestCase):
    ALLOW = {"api.example.test"}

    def test_accepts_exact_allowlisted_https_host(self):
        target = validate_outbound_url("https://API.EXAMPLE.TEST/v1/items?q=1", self.ALLOW)
        self.assertEqual(target.hostname, "api.example.test")
        self.assertEqual(target.url, "https://api.example.test/v1/items?q=1")

    def test_rejects_http_and_nonstandard_ports(self):
        for url in ("http://api.example.test/", "https://api.example.test:8443/"):
            with self.subTest(url=url), self.assertRaises(OutboundRequestError):
                validate_outbound_url(url, self.ALLOW)

    def test_rejects_untrusted_and_suffix_hosts(self):
        for host in ("api.example.test.attacker.invalid", "attacker.invalid",
                     "localhost", "service.local"):
            with self.subTest(host=host), self.assertRaises(OutboundRequestError):
                validate_outbound_url(f"https://{host}/", self.ALLOW)

    def test_rejects_ip_literals_and_credentials(self):
        for url in ("https://127.0.0.1/", "https://[::1]/",
                    "https://user:pass@api.example.test/"):
            with self.subTest(url=url), self.assertRaises(OutboundRequestError):
                validate_outbound_url(url, self.ALLOW)

    def test_rejects_fragments_and_malformed_ports(self):
        for url in ("https://api.example.test/#fragment",
                    "https://api.example.test:bad/"):
            with self.subTest(url=url), self.assertRaises(OutboundRequestError):
                validate_outbound_url(url, self.ALLOW)

    def test_empty_allowlist_fails_closed(self):
        with self.assertRaises(OutboundRequestError):
            validate_outbound_url("https://api.example.test/", set())


class UpstreamResponseTests(unittest.TestCase):
    def test_accepts_small_json_object(self):
        self.assertEqual(
            validate_upstream_json(b'{"ok":true}', "application/json; charset=utf-8"),
            {"ok": True},
        )

    def test_rejects_wrong_content_type_and_non_object_root(self):
        for body, content_type in (
            (b'{"ok":true}', "text/html"),
            (b'[1,2]', "application/json"),
            (b'"text"', "application/json"),
        ):
            with self.subTest(body=body), self.assertRaises(OutboundRequestError):
                validate_upstream_json(body, content_type)

    def test_rejects_invalid_utf8_and_invalid_json(self):
        for body in (b'\xff', b'{broken'):
            with self.subTest(body=body), self.assertRaises(OutboundRequestError):
                validate_upstream_json(body, "application/json")

    def test_rejects_duplicate_keys(self):
        with self.assertRaisesRegex(OutboundRequestError, "duplicate"):
            validate_upstream_json(b'{"role":"user","role":"admin"}', "application/json")

    def test_enforces_body_size_limit(self):
        with self.assertRaisesRegex(OutboundRequestError, "size limit"):
            validate_upstream_json(b'{"payload":"' + b'x' * 100 + b'"}',
                                   "application/json", max_bytes=32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
