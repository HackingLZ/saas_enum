import contextlib
import copy
import csv
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import txt_enum
from modules.txt_dns import TXTResolver, decode_txt, normalize_domain, parse_response
from modules.txt_matcher import analyze, discover, load_rules, match_query, spf_references
from modules.txt_storage import save_database, summary

CATALOG = load_rules()


def query(name="example.com", values=(), status="ok", scope="apex"):
    return {"query_name": name, "record_type": "TXT", "scope": scope, "via": [],
            "fetched_at": "2026-11-23T00:00:00Z", "resolver": "fixture", "status": status,
            "source_url": "https://example.invalid/test-fixture", "rcode": 0,
            "records": [{"owner": name, "value": value, "raw": value, "ttl": 300} for value in values]}


class FakeResolver:
    def __init__(self, data):
        self.data = data
        self.calls = []

    def query(self, name):
        self.calls.append(name)
        return copy.deepcopy(self.data.get(name, query(name, status="no_data")))


class DNSParsingTests(unittest.TestCase):
    def test_split_character_strings_and_decimal_escapes(self):
        self.assertEqual(decode_txt('"google-site-" "verification=abc"'), "google-site-verification=abc")
        self.assertEqual(decode_txt(r'"a\032b\034c\092d"'), 'a b"c\\d')
        self.assertEqual(decode_txt("google-site-verification=abc"), "google-site-verification=abc")

    def test_malformed_txt_is_not_partially_matched(self):
        for value in ('"unfinished', '"valid" trailing', r'"bad\999"'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_txt(value)

    def test_normalization_and_validation(self):
        self.assertEqual(normalize_domain("EXAMPLE.COM."), "example.com")
        self.assertEqual(normalize_domain("bücher.de"), "xn--bcher-kva.de")
        self.assertEqual(normalize_domain("_spf.example.com"), "_spf.example.com")
        for value in ("https://example.com", "a..com", "a b.com", "127.0.0.1", "-a.com", "localhost", "a" * 64 + ".com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)

    def test_cname_chain_filters_unrelated_answers(self):
        payload = {"Status": 0, "Answer": [
            {"name": "example.com.", "type": 5, "data": "alias.example.net."},
            {"name": "alias.example.net.", "type": 16, "TTL": 5, "data": '"a" "b"'},
            {"name": "example.com.", "type": 1, "data": "1.2.3.4"},
            {"name": "unrelated.com.", "type": 16, "data": "fake"},
        ]}
        result = parse_response("example.com", payload, "fixture", "fixture")
        self.assertEqual([(r["owner"], r["value"]) for r in result["records"]], [("alias.example.net", "ab")])

    def test_separate_records_are_not_joined(self):
        payload = {"Status": 0, "Answer": [
            {"name": "example.com", "type": 16, "data": '"google-site-"'},
            {"name": "example.com", "type": 16, "data": '"verification=abc"'}]}
        result = parse_response("example.com", payload, "fixture", "fixture")
        self.assertEqual(match_query(result, CATALOG), [])

    def test_dns_statuses_remain_distinct(self):
        for payload, status in [({"Status": 0}, "no_data"), ({"Status": 3}, "nxdomain"),
                                ({"Status": 2}, "servfail"), ({"Status": 5}, "refused"),
                                ({"Status": 0, "TC": True}, "truncated")]:
            self.assertEqual(parse_response("example.com", payload, "fixture", "fixture")["status"], status)
        with self.assertRaises(ValueError):
            parse_response("example.com", {}, "fixture", "fixture")

    def test_transport_failure_is_not_empty_dns(self):
        with patch("urllib.request.urlopen", side_effect=TimeoutError("fixture timeout")):
            result = TXTResolver(retries=0).query("example.com")
        self.assertEqual(result["status"], "error")
        self.assertIn("fixture timeout", result["error"])

    def test_retry_then_success(self):
        response = io.BytesIO(b'{"Status":0}')
        with patch("urllib.request.urlopen", side_effect=[TimeoutError(), response]) as request, patch("time.sleep"):
            result = TXTResolver(rate=10000, retries=1).query("example.com")
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["status"], "no_data")

    def test_malformed_answer_is_a_failed_query_not_empty_dns(self):
        for answer in ([None], [{"name": None, "type": 16, "data": "abc"}],
                       [{"name": "example.com", "type": 5, "data": 42}]):
            with self.subTest(answer=answer):
                response = io.BytesIO(json.dumps({"Status": 0, "Answer": answer}).encode())
                with patch("urllib.request.urlopen", return_value=response):
                    result = TXTResolver(retries=0).query("example.com")
                self.assertEqual(result["status"], "error")
                self.assertIn("Invalid DNS JSON", result["error"])


class MatchingTests(unittest.TestCase):
    def test_google_token_is_not_workspace(self):
        matches = match_query(query(values=["google-site-verification=abc"]), CATALOG)
        self.assertEqual([m["service"] for m in matches], ["Google domain verification"])

    def test_marker_must_be_at_start_and_have_a_token(self):
        values = ["note: google-site-verification=abc", "google-site-verification=", "hello stripe-verification=abc"]
        self.assertEqual(match_query(query(values=values), CATALOG), [])

    def test_no_vendor_substring_or_domain_suffix_false_positive(self):
        values = ["v=spf1 include:sendgrid.net.evil.com include:evil-sendgrid.net -all", "I use Google and Slack"]
        self.assertEqual(match_query(query(values=values), CATALOG), [])

    def test_positive_spf_references_only(self):
        value = "v=spf1 -include:sendgrid.net ~include:mailgun.org ?include:amazonses.com +include:mail.zendesk.com redirect=_spf.google.com"
        self.assertEqual([r["domain"] for r in spf_references(value)], ["mail.zendesk.com", "_spf.google.com"])
        self.assertEqual({m["service"] for m in match_query(query(values=[value]), CATALOG)}, {"Zendesk", "Google mail"})

    def test_dynamic_vendor_verification_marker(self):
        result = match_query(query(values=["anthropic-domain-verification-abc123=opaque"]), CATALOG)
        self.assertEqual(result[0]["service"], "Anthropic")
        self.assertEqual(result[0]["confidence"], "medium")

    def test_do_not_attribute_upstream_verification_to_customer(self):
        values = ["stripe-verification=abc", "v=spf1 include:sendgrid.net -all"]
        matches = match_query(query("_spf.provider.com", values, scope="spf"), CATALOG)
        self.assertEqual([m["service"] for m in matches], ["Twilio SendGrid"])

    def test_dmarc_reporting_scope_and_host_boundary(self):
        value = "v=DMARC1; p=none; rua=mailto:reports@inbound.postmarkapp.com!10m"
        self.assertEqual(match_query(query(values=[value]), CATALOG), [])
        self.assertEqual(match_query(query(values=[value], scope="dmarc"), CATALOG)[0]["signal"], "dmarc_reporting")
        self.assertEqual(match_query(query(values=[value.replace("postmarkapp.com", "postmarkapp.com.evil.com")], scope="dmarc"), CATALOG), [])

    def test_unknown_tokens_not_automatically_labeled(self):
        result = analyze({"domain": "example.com", "queries": [query(values=["mystery-domain-verification=abc", "00D123456789=xyz"])]}, CATALOG)
        self.assertEqual(result["services"], [])
        self.assertEqual(len(discover([result])), 2)

    def test_unknown_spf_in_partially_matched_record(self):
        result = analyze({"domain": "example.com", "queries": [query(values=["v=spf1 include:sendgrid.net include:unknown.example -all"])]}, CATALOG)
        self.assertEqual(discover([result])[0]["pattern"], "unknown.example")

    def test_all_same_provider_references_are_accounted_for(self):
        result = analyze({"domain": "example.com", "queries": [query(values=[
            "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com -all"])]}, CATALOG)
        self.assertEqual(len(result["matches"]), 2)
        self.assertEqual(discover([result]), [])

    def test_duplicate_service_evidence_aggregates(self):
        result = analyze({"domain": "example.com", "queries": [query(values=["google-site-verification=one", "google-site-verification=two"])]}, CATALOG)
        self.assertEqual(len(result["services"]), 1)
        self.assertEqual(result["services"][0]["evidence_count"], 2)


class ScanTests(unittest.TestCase):
    def test_upstream_provider_is_labeled_inherited_in_all_exports(self):
        resolver = FakeResolver({
            "example.com": query(values=["v=spf1 include:_spf.bridge.example -all"]),
            "_spf.bridge.example": query("_spf.bridge.example", ["v=spf1 include:sendgrid.net -all"]),
        })
        result = txt_enum.scan_domain("example.com", resolver, CATALOG, dmarc=False)
        service = next(s for s in result["services"] if s["service"] == "Twilio SendGrid")
        self.assertEqual(service["association"], "inherited")
        self.assertEqual(service["direct_evidence_count"], 0)
        self.assertEqual(service["inherited_evidence_count"], 1)
        self.assertEqual(result["matches"][0]["association"], "inherited")
        self.assertEqual(summary([result])["direct_company_service_pairs"], 0)
        self.assertEqual(summary([result])["inherited_only_company_service_pairs"], 1)
        self.assertIn("inherited via SPF", txt_enum.render([result], {}, "text"))
        row = next(csv.DictReader(io.StringIO(txt_enum.render([result], {}, "csv"))))
        self.assertEqual(row["association"], "inherited")

    def test_direct_and_inherited_evidence_are_counted_separately(self):
        resolver = FakeResolver({
            "example.com": query(values=["v=spf1 include:sendgrid.net include:_spf.bridge.example -all"]),
            "_spf.bridge.example": query("_spf.bridge.example", ["v=spf1 include:sendgrid.net -all"]),
        })
        result = txt_enum.scan_domain("example.com", resolver, CATALOG, dmarc=False)
        service = next(s for s in result["services"] if s["service"] == "Twilio SendGrid")
        self.assertEqual(service["association"], "direct")
        self.assertEqual(service["direct_evidence_count"], 1)
        self.assertEqual(service["inherited_evidence_count"], 1)
        self.assertEqual(summary([result])["direct_company_service_pairs"], 1)
        self.assertEqual(summary([result])["inherited_only_company_service_pairs"], 0)

    def test_spf_cycle_and_provenance(self):
        resolver = FakeResolver({
            "example.com": query(values=["v=spf1 include:_spf.example.com -all"]),
            "_spf.example.com": query("_spf.example.com", ["v=spf1 include:example.com include:sendgrid.net -all"]),
        })
        result = txt_enum.scan_domain("example.com", resolver, CATALOG, dmarc=False, spf_depth=4)
        self.assertEqual(len(resolver.calls), len(set(resolver.calls)))
        match = result["matches"][0]
        self.assertEqual(match["via"], ["example.com"])
        self.assertEqual(match["query_name"], "_spf.example.com")

    def test_query_budget_and_macro(self):
        resolver = FakeResolver({"example.com": query(values=["v=spf1 include:a.example.com include:b.example.com -all"])})
        result = txt_enum.scan_domain("example.com", resolver, CATALOG, max_queries=2)
        self.assertEqual(len(resolver.calls), 2)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(any("budget" in s for s in result["warnings"]))
        resolver = FakeResolver({"example.com": query(values=["v=spf1 include:%{ir}.spf.has.pphosted.com -all"])})
        result = txt_enum.scan_domain("example.com", resolver, CATALOG, dmarc=False)
        self.assertEqual(resolver.calls, ["example.com"])
        self.assertEqual(result["matches"][0]["service"], "Proofpoint")

    def test_apex_only_does_one_txt_query(self):
        resolver = FakeResolver({"example.com": query(values=["v=spf1 include:_spf.google.com -all"])})
        result = txt_enum.scan_domain("example.com", resolver, CATALOG, dmarc=False, spf_depth=0)
        self.assertEqual(resolver.calls, ["example.com"])
        self.assertEqual(result["status"], "ok")

    def test_missing_record_is_not_transport_failure(self):
        for status, expected in [("no_data", "no_data"), ("nxdomain", "nxdomain"), ("error", "error")]:
            resolver = FakeResolver({"example.com": query(status=status)})
            self.assertEqual(txt_enum.scan_domain("example.com", resolver, CATALOG, dmarc=False)["status"], expected)


class OutputTests(unittest.TestCase):
    def test_conflicting_output_paths_fail_before_dns_and_preserve_files(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "existing.json"
            output.write_text("keep this file")
            with patch("modules.txt_dns.TXTResolver.query") as request, \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                txt_enum.main(["--domain", "example.com", "--output", str(output), "--raw-output", str(output)])
            self.assertEqual(caught.exception.code, 2)
            request.assert_not_called()
            self.assertEqual(output.read_text(), "keep this file")

    def test_sqlite_history_and_record_links(self):
        result = txt_enum.scan_domain("example.com", FakeResolver({"example.com": query(values=["stripe-verification=abc"])}), CATALOG, dmarc=False)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mapping.sqlite"
            for _ in range(2):
                save_database(path, [result], {"created_at": "fixture"})
            with contextlib.closing(sqlite3.connect(path)) as db, db:
                self.assertEqual(db.execute("select count(*) from runs").fetchone()[0], 2)
                self.assertEqual(db.execute("select value from matches join records on records.id=matches.record_id").fetchall(), [("stripe-verification=abc",)] * 2)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_json_csv_and_offline_cli_replay(self):
        result = txt_enum.scan_domain("example.com", FakeResolver({"example.com": query(values=["stripe-verification=abc"])}), CATALOG, dmarc=False)
        with tempfile.TemporaryDirectory() as temp:
            source, output = Path(temp) / "raw.jsonl", Path(temp) / "report.json"
            source.write_text(json.dumps(result) + "\n")
            with patch("urllib.request.urlopen", side_effect=AssertionError("Replay must be offline")), contextlib.redirect_stderr(io.StringIO()):
                rc = txt_enum.main(["--replay", str(source), "--format", "json", "--output", str(output)])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(output.read_text())["summary"]["company_service_pairs"], 1)
            self.assertIn("stripe-verification=abc", txt_enum.render([result], {}, "csv"))
            self.assertEqual(txt_enum.safe_csv("=1+1"), "'=1+1")


    def test_ambiguous_abbreviations_stay_unknown(self):
        self.assertEqual(match_query(query(values=["h1-domain-verification=abc", "rzp-site-verification=abc"]), CATALOG), [])

    def test_csv_escapes_imported_fields_for_domains_without_matches(self):
        result = txt_enum.scan_domain("example.com", FakeResolver({}), CATALOG, dmarc=False)
        result.update(domain="=1+1", status="+1", collected_at="-1+1",
                      collection_method="@SUM(1,1)")
        rows = list(csv.reader(io.StringIO(txt_enum.render([result], {}, "csv"))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1], ["'=1+1", "'+1", "", "", "", "", "", "", "", "", "'-1+1", "'@SUM(1,1)", ""])
        # Escaping belongs only in CSV, so JSON evidence keeps its original values.
        exported = json.loads(txt_enum.render([result], {}, "json"))["results"][0]
        self.assertEqual(exported["domain"], "=1+1")
        self.assertEqual(exported["collection_method"], "@SUM(1,1)")


if __name__ == "__main__":
    unittest.main()
