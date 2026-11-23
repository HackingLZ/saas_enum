import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from urllib.parse import urlsplit

from modules.txt_matcher import DEFAULT_RULES, load_rules
from scripts.build_catalog_db import build_database


class CatalogDatabaseTests(unittest.TestCase):
    def test_build_contains_rules_and_source_hash_without_scan_tables(self):
        catalog = load_rules()
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "data" / "rules.sqlite"
            self.assertEqual(build_database(DEFAULT_RULES, output), len(catalog["rules"]))
            with sqlite3.connect(output) as db:
                rules = [json.loads(row[0]) for row in db.execute(
                    "SELECT rule_json FROM fingerprints ORDER BY rule_id")]
                self.assertEqual(rules, sorted(catalog["rules"], key=lambda r: r["id"]))
                metadata = dict(db.execute("SELECT key, value FROM catalog_metadata"))
                self.assertEqual(metadata["version"], catalog["version"])
                self.assertEqual(metadata["file_sha256"], hashlib.sha256(DEFAULT_RULES.read_bytes()).hexdigest())
                tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertEqual(tables, {"fingerprints", "catalog_metadata"})
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_existing_database_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "existing.sqlite"
            with sqlite3.connect(output) as db:
                db.execute("CREATE TABLE local_results (value TEXT)")
                db.execute("INSERT INTO local_results VALUES ('keep this result')")
            before = output.read_bytes()
            with self.assertRaises(FileExistsError):
                build_database(DEFAULT_RULES, output)
            self.assertEqual(output.read_bytes(), before)

    def test_empty_sources_require_explicit_withholding_and_medium_confidence(self):
        catalog = load_rules()
        catalog["rules"] = [copy.deepcopy(catalog["rules"][0])]
        rule = catalog["rules"][0]
        rule["sources"] = []
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "catalog.json"
            for confidence, withheld, valid in [
                ("medium", True, True), ("medium", False, False), ("high", True, False)
            ]:
                with self.subTest(confidence=confidence, withheld=withheld):
                    rule.update(confidence=confidence, observation_sources_withheld=withheld)
                    path.write_text(json.dumps(catalog))
                    if valid:
                        self.assertEqual(load_rules(path), catalog)
                    else:
                        with self.assertRaises(ValueError):
                            load_rules(path)

    def test_distributable_catalog_excludes_observation_provenance(self):
        catalog = load_rules()
        self.assertNotIn("evidence_files", catalog)
        lookup_hosts = {"dns.google", "cloudflare-dns.com", "who.is", "whoisfreaks.com"}
        for rule in catalog["rules"]:
            with self.subTest(rule=rule["id"]):
                self.assertNotIn("observed_domains", rule)
                self.assertNotIn("examples", rule)
                self.assertTrue(all(urlsplit(s).hostname not in lookup_hosts for s in rule["sources"]))
                if rule["confidence"] == "high":
                    self.assertTrue(rule["sources"])


if __name__ == "__main__":
    unittest.main()
