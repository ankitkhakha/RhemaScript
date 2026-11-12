import unittest

from raei.api_contracts import AuthorizationError, Principal, RequestError
from raei.api_security_lab import SecureRecordAPI, WindowLimiter


class SecureRecordAPITests(unittest.TestCase):
    def setUp(self):
        self.api = SecureRecordAPI()
        self.api.create("DOC-1", "alice", "Draft", "private body")
        self.alice = Principal("alice", frozenset({"contributor"}))
        self.bob = Principal("bob", frozenset({"contributor"}))
        self.reader = Principal("alice", frozenset({"reader"}))
        self.admin = Principal("root", frozenset({"administrator"}))

    def test_owner_can_read_own_record(self):
        self.assertEqual(self.api.read(self.alice, "DOC-1")["title"], "Draft")

    def test_other_contributor_cannot_read_or_update_foreign_record(self):
        with self.assertRaises(AuthorizationError):
            self.api.read(self.bob, "DOC-1")
        with self.assertRaises(AuthorizationError):
            self.api.update(self.bob, "DOC-1", {"title": "stolen"}, 1)

    def test_reader_cannot_update(self):
        with self.assertRaises(AuthorizationError):
            self.api.update(self.reader, "DOC-1", {"title": "changed"}, 1)

    def test_owner_cannot_mass_assign_owner_classification_or_version(self):
        for field in ("owner", "classification", "version", "is_admin"):
            with self.subTest(field=field):
                with self.assertRaises(RequestError):
                    self.api.update(self.alice, "DOC-1", {field: "attacker"}, 1)

    def test_owner_can_update_allowed_field_with_current_version(self):
        result = self.api.update(self.alice, "DOC-1", {"title": "Revised"}, 1)
        self.assertEqual(result["version"], 2)
        self.assertEqual(self.api.read(self.alice, "DOC-1")["title"], "Revised")

    def test_stale_update_is_rejected(self):
        self.api.update(self.alice, "DOC-1", {"title": "Revised"}, 1)
        with self.assertRaisesRegex(RequestError, "stale version"):
            self.api.update(self.alice, "DOC-1", {"title": "Lost update"}, 1)

    def test_reader_view_hides_private_classification_and_owner(self):
        visible = self.api.read(self.alice, "DOC-1")
        self.assertNotIn("classification", visible)
        self.assertNotIn("owner", visible)

    def test_admin_can_read_and_update_any_record_and_delete(self):
        self.assertEqual(self.api.read(self.admin, "DOC-1")["owner"], "alice")
        self.api.update(self.admin, "DOC-1", {"classification": "restricted"}, 1)
        self.api.delete(self.admin, "DOC-1")
        with self.assertRaises(RequestError):
            self.api.read(self.admin, "DOC-1")

    def test_anonymous_is_denied(self):
        with self.assertRaises(AuthorizationError):
            self.api.read(None, "DOC-1")

    def test_audit_records_denials_without_record_body(self):
        with self.assertRaises(AuthorizationError):
            self.api.read(self.bob, "DOC-1")
        event = self.api.audit[-1]
        self.assertEqual(event.outcome, "denied")
        self.assertFalse(hasattr(event, "body"))

    def test_rate_limit_is_applied(self):
        api = SecureRecordAPI(limiter=WindowLimiter(1, 60))
        api.create("DOC-2", "alice", "Title", "Body")
        api.read(self.alice, "DOC-2")
        with self.assertRaisesRegex(RequestError, "request limit"):
            api.read(self.alice, "DOC-2")

    def test_window_limiter_expires_old_events(self):
        limiter = WindowLimiter(1, 10)
        self.assertTrue(limiter.allow("alice", now=0))
        self.assertFalse(limiter.allow("alice", now=5))
        self.assertTrue(limiter.allow("alice", now=10))


if __name__ == "__main__":
    unittest.main(verbosity=2)
