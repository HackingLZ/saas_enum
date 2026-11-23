import json
import tempfile
import unittest
from pathlib import Path

import txt_enum
from modules.txt_matcher import analyze, discover, load_rules, match_query
from test_txt_enum import query

CATALOG = load_rules()


class ExpandedMappingTests(unittest.TestCase):
    def services(self, values):
        return {m['service'] for m in match_query(query(values=values), CATALOG)}

    def test_pardot_account_formats_and_invalid_near_matches(self):
        token = 'a' * 64
        self.assertEqual(self.services(['pardot123456=' + token, 'pardot_12345_*=' + token]),
                         {'Salesforce Account Engagement / Pardot'})
        self.assertEqual(self.services(['pardotcustomer=' + token, 'unrelated=pardot123=' + token,
                                        'pardot123=', 'pardot123=not-a-hash']), set())

    def test_separator_variants_are_explicit(self):
        self.assertEqual(self.services(['applause-verification:abcd', 'zoom-domain-verification = abcd']),
                         {'Applause', 'Zoom'})
        self.assertEqual(self.services(['google-site-verification: abcd', 'MS=ms1234 1 Hour']), set())

    def test_documented_marker_and_sibling_scope(self):
        value = 'cloudflare_dashboard_sso=abc123'
        self.assertEqual(self.services([value]), {'Cloudflare dashboard SSO'})
        self.assertEqual(match_query(query(values=[value], scope='spf'), CATALOG), [])
        self.assertEqual(self.services(['cloudflare_dashboard_sso_evil=abc123', 'note=' + value]), set())

    def test_spf_provider_macro_and_domain_boundary(self):
        self.assertEqual(self.services(['v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email -all']),
                         {'Valimail'})
        self.assertEqual(self.services(['v=spf1 include:_spf.mailersend.net.attacker.example -all',
                                       'v=spf1 -include:spf.smtp2go.com -all']), set())

    def test_exact_domain_alias_does_not_duplicate_subdomain_rule(self):
        matches = match_query(query(values=['v=spf1 include:spf.mandrillapp.com -all']), CATALOG)
        self.assertEqual([m['rule_id'] for m in matches], ['spf-mandrill'])
        matches = match_query(query(values=['v=spf1 include:mandrillapp.com -all']), CATALOG)
        self.assertEqual([m['rule_id'] for m in matches], ['spf-mailchimp-transactional-alternate'])

    def test_unknown_grouping_preserves_formats_and_opaque_tokens(self):
        result = {'domain': 'example.com', 'queries': [query(values=[
            'pardot123=abc', 'pardot456=def', 'sending_domain123=abc', 'sending_domain999=def',
            'unlisted-cloud-verification-abc12345', 'unlisted-site-verification_abc12345',
            'abcdefghijklmnopqrstuvwx==', 'abcdefghijklmnopqrstuvwx=', 'ABC123._autotask'])], 'matches': []}
        groups = {(x['kind'], x['pattern']): x for x in discover([result])}
        self.assertEqual(groups[('txt_prefix', 'pardot<account-id>')]['record_count'], 2)
        self.assertEqual(groups[('txt_prefix', 'sending_domain<account-id>')]['record_count'], 2)
        self.assertIn(('txt_marker', 'unlisted-cloud-verification-<token>'), groups)
        self.assertIn(('txt_marker', 'unlisted-site-verification_<token>'), groups)
        self.assertIn(('txt_suffix', '_autotask'), groups)
        self.assertEqual(groups[('opaque', 'unattributed-token')]['record_count'], 2)


class ImportAndStudyTests(unittest.TestCase):
    def test_live_import_preserves_provenance_and_dns_status(self):
        rows = [{'domain': 'example.com', 'retrieved_at': '2026-11-23T19:00:00Z',
                 'source_url': 'https://dns.google/resolve?name=example.com&type=TXT',
                 'provider': 'google', 'transport': 'fixture_doh',
                 'payload': {'Status': 0, 'AD': True, 'Answer': [
                     {'name': 'example.com.', 'type': 16, 'TTL': 300, 'data': '"google-site-" "verification=abc"'}]}},
                {'domain': 'empty.example', 'retrieved_at': '2026-11-23T19:00:00Z',
                 'source_url': 'fixture', 'payload': {'Status': 0}}]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.jsonl'
            path.write_text('\n'.join(json.dumps(r) for r in rows))
            results = txt_enum.import_web(path, CATALOG, live=True)
        self.assertEqual(results[0]['collection_method'], 'live_doh_import')
        self.assertEqual(results[0]['queries'][0]['transport'], 'fixture_doh')
        self.assertTrue(results[0]['queries'][0]['dnssec_authenticated'])
        self.assertEqual(results[0]['queries'][0]['records'][0]['value'], 'google-site-verification=abc')
        self.assertNotIn('web tool', ' '.join(results[0]['warnings']))
        self.assertEqual(results[1]['status'], 'no_data')

    def test_live_import_rejects_web_table(self):
        row = {'domain': 'example.com', 'extracted_records': [{'owner': 'example.com', 'value': 'abc'}]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.jsonl'
            path.write_text(json.dumps(row))
            with self.assertRaises(ValueError):
                txt_enum.import_web(path, CATALOG, live=True)


if __name__ == '__main__':
    unittest.main()
