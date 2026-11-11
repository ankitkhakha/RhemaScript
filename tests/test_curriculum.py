import unittest
from raei.curriculum import BIBLE_BOOKS, build_registry, registry_summary

class CurriculumRegistryTests(unittest.TestCase):
    def test_all_66_books_are_registered(self):
        self.assertEqual(66, len(BIBLE_BOOKS))
        units = [u for u in build_registry() if u["domain"] == "whole_bible"]
        self.assertEqual(66, len(units))
        self.assertEqual(BIBLE_BOOKS, [u["title"] for u in units])

    def test_all_capabilities_and_interfaces_are_registered(self):
        ids = {u["id"] for u in build_registry()}
        self.assertTrue(all("CAP-%02d" % n in ids for n in range(1,16)))
        self.assertTrue(all("IF-%02d" % n in ids for n in range(1,19)))

    def test_registry_is_unique_and_unassessed(self):
        units = build_registry()
        ids = [u["id"] for u in units]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(u["status"] == "not_started" for u in units))
        self.assertTrue(all(u["evidence_required"] for u in units))

    def test_summary_discloses_scope_and_status(self):
        summary = registry_summary()
        self.assertEqual(66, summary["bible_book_count"])
        self.assertEqual(10, summary["ethics_case_count"])
        self.assertEqual("curriculum_defined_not_assessed", summary["status"])
        self.assertEqual(len(build_registry()), summary["total_units"])

if __name__ == "__main__":
    unittest.main()
