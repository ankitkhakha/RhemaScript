import unittest

from raei.security_config import audit_security_config


GOOD = {
    "debug": False, "tls_required": True, "secure_cookies": True,
    "http_only_cookies": True, "same_site": "Lax", "csrf_protection": True,
    "cors_allowed_origins": ["https://app.example.test"],
    "trusted_proxy_hops": 1, "session_secret": "s" * 40,
    "security_headers": {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000",
    },
}


class SecurityConfigTests(unittest.TestCase):
    def test_secure_configuration_has_no_findings(self):
        self.assertEqual(audit_security_config(GOOD), [])

    def test_missing_and_unsafe_settings_are_reported(self):
        bad = dict(GOOD)
        bad.update(debug=True, tls_required=False, secure_cookies=False,
                   http_only_cookies=False, same_site="None",
                   csrf_protection=False, cors_allowed_origins=["*"],
                   trusted_proxy_hops=-1, session_secret="tiny",
                   security_headers={})
        findings = audit_security_config(bad)
        self.assertGreaterEqual(len(findings), 9)
        self.assertTrue(any("wildcard CORS" in item for item in findings))
        self.assertTrue(any("missing security headers" in item for item in findings))

    def test_partial_or_non_object_config_fails_closed(self):
        self.assertTrue(audit_security_config({}))
        self.assertTrue(audit_security_config(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
