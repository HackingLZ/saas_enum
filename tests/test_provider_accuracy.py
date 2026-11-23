"""Synthetic provider checks; install requirements.txt to run this suite."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

DEPENDENCIES = all(importlib.util.find_spec(name) for name in ("dns", "requests", "bs4", "yaml", "rich"))
if DEPENDENCIES:
    import dns.exception
    import dns.resolver
    import requests
    from bs4 import BeautifulSoup
    import saas_enum
    from modules import dns_utils, web_analysis


def response(html, url, status=200):
    mock = MagicMock()
    mock.__enter__.return_value = mock
    mock.text, mock.url, mock.status_code, mock.history = html, url, status, []
    return mock


def dns_result(address="192.0.2.1", status="ok"):
    return {"all": [address] if address else [], "details": {"A": [address] if address else []},
            "status": status, "errors": {"A": "fixture timeout"} if status == "error" else {}}


@unittest.skipUnless(DEPENDENCIES, "Provider-mode tests require requirements.txt; TXT mode has no dependencies")
class PageEvidenceTests(unittest.TestCase):
    def analyze(self, html, url="https://provider.example/"):
        soup = BeautifulSoup(html, "html.parser")
        result = {"web_check": {}}
        found, evidence, strength = web_analysis.analyze_webpage_content(
            "acme", soup, soup.get_text(" "), url, result)
        return found, strength, result["web_check"]

    def test_generic_sso_is_not_company_evidence(self):
        found, strength, web = self.analyze("<title>Sign in</title>Continue", "https://login.example/sso?tenant=acme")
        self.assertFalse(found)
        self.assertEqual(strength, "none")
        self.assertTrue(web["authentication_flow"])

    def test_company_substrings_do_not_identify_tenant(self):
        found, strength, _ = self.analyze("<title>Acmeology</title>Welcome to notacme", "https://notacme.provider.example/")
        self.assertFalse(found)
        self.assertEqual(strength, "none")

    def test_missing_tenant_and_placeholder_pages_are_negative(self):
        for text in ("Acme tenant not found", "Acme workspace does not exist", "Acme coming soon"):
            with self.subTest(text=text):
                found, strength, web = self.analyze("<title>Acme</title>" + text, "https://acme.provider.example/")
                self.assertFalse(found)
                self.assertEqual(strength, "none")
                self.assertTrue(web["negative_evidence"])

    def test_echoed_hostname_and_form_action_are_only_weak_evidence(self):
        found, strength, _ = self.analyze(
            '<p>Continue to https://acme.provider.example/</p><form action="/acme/login"></form>',
            "https://acme.provider.example/")
        self.assertTrue(found)
        self.assertEqual(strength, "weak")

    def test_explicit_company_name_is_potential_page_evidence(self):
        found, strength, _ = self.analyze("<title>Acme</title>Welcome to the Acme workspace")
        self.assertTrue(found)
        self.assertEqual(strength, "strong")

    def test_page_fetch_verifies_tls_and_ignores_script_contents(self):
        fixture = response('<title>Login</title><script>var company="acme";</script>', "https://provider.example/login")
        with patch("modules.web_analysis.requests.get", return_value=fixture) as get:
            found, _, _, strength = web_analysis.check_webpage_content(
                "https://provider.example/", "acme", {"web_check": dns_utils.empty_web_check()})
        self.assertFalse(found)
        self.assertEqual(strength, "none")
        self.assertIs(get.call_args.kwargs["verify"], True)


@unittest.skipUnless(DEPENDENCIES, "Provider-mode tests require requirements.txt")
class ControlComparisonTests(unittest.TestCase):
    real_url = "https://acme.provider.example/"
    fake_url = "https://randomcontroltest.provider.example/"

    def scan(self, replies, fake_dns=None):
        with patch("modules.dns_utils.generate_random_subdomain", return_value="randomcontroltest"), \
             patch("modules.dns_utils.resolve_hostname", side_effect=[dns_result(), fake_dns or dns_result("192.0.2.2")]), \
             patch("modules.web_analysis.requests.get", side_effect=replies) as get:
            result = dns_utils.dns_check("Fixture", "SHORT_NAME.provider.example", "acme", timeout=20)
        return result, get

    def test_same_login_destination_with_different_state_is_unconfirmed(self):
        result, get = self.scan([
            response("<title>Acme</title>Continue to sign in", "https://identity.example/oauth2?tenant=acme&state=one"),
            response("<title>Login</title>Continue", "https://identity.example/oauth2?tenant=randomcontroltest&state=two"),
        ])
        self.assertEqual(get.call_count, 2)
        self.assertEqual(result["control_check"]["verdict"], "shared_login")
        self.assertEqual(result["status"], "wildcard_match")
        self.assertFalse(result["active_use_verified"])

    def test_template_echoing_any_tenant_is_unconfirmed(self):
        result, _ = self.scan([
            response("<title>Acme</title>Welcome Acme", self.real_url),
            response("<title>randomcontroltest</title>Welcome randomcontroltest", self.fake_url),
        ])
        self.assertEqual(result["control_check"]["verdict"], "shared_page")
        self.assertEqual(result["status"], "wildcard_match")
        # Different random/real IPs must not bypass the control comparison.
        self.assertTrue(result["wildcard_dns"])

    def test_random_name_in_different_template_is_still_unconfirmed(self):
        result, _ = self.scan([
            response("<title>Acme</title>Welcome to your workspace", self.real_url),
            response("<title>randomcontroltest</title>Start a new workspace", self.fake_url),
        ])
        self.assertEqual(result["control_check"]["verdict"], "reflected_name")
        self.assertEqual(result["association"], "candidate")

    def test_distinct_page_evidence_can_be_corroborated_but_not_active_use(self):
        result, _ = self.scan([
            response("<title>Acme</title>Acme staff workspace", self.real_url),
            response("Unknown workspace", self.fake_url, 404),
        ])
        self.assertEqual(result["status"], "confirmed_via_web")
        self.assertEqual(result["association"], "corroborated")
        self.assertEqual(result["control_check"]["verdict"], "different")
        self.assertFalse(result["active_use_verified"])

    def test_control_timeout_or_access_denial_cannot_confirm(self):
        for control in (requests.Timeout("fixture"), response("Access denied", self.fake_url, 403)):
            with self.subTest(control=type(control).__name__):
                result, _ = self.scan([response("<title>Acme</title>Acme workspace", self.real_url), control])
                self.assertEqual(result["control_check"]["verdict"], "inconclusive")
                self.assertEqual(result["association"], "candidate")

    def test_failed_control_dns_does_not_look_like_nonexistent_tenant(self):
        result, get = self.scan([response("<title>Acme</title>Acme workspace", self.real_url)], dns_result(None, "error"))
        self.assertEqual(get.call_count, 1)
        self.assertEqual(result["control_check"]["verdict"], "inconclusive")
        self.assertEqual(result["association"], "candidate")

    def test_absent_control_dns_and_distinct_company_page(self):
        result, get = self.scan([response("<title>Acme</title>Acme workspace", self.real_url)], dns_result(None, "nxdomain"))
        self.assertEqual(get.call_count, 1)
        self.assertEqual(result["status"], "confirmed_valid")
        self.assertEqual(result["control_check"]["verdict"], "no_control_dns")

    def test_candidate_dns_failure_is_not_reported_as_no_record(self):
        with patch("modules.dns_utils.resolve_hostname", return_value=dns_result(None, "error")), \
             patch("modules.web_analysis.requests.get") as get:
            result = dns_utils.dns_check("Fixture", "SHORT_NAME.provider.example", "acme")
        self.assertEqual(result["status"], "error")
        get.assert_not_called()


@unittest.skipUnless(DEPENDENCIES, "Provider-mode tests require requirements.txt")
class ProviderDNSTests(unittest.TestCase):
    def test_nxdomain_stops_further_queries(self):
        with patch("modules.dns_utils.dns.resolver.Resolver") as factory:
            factory.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
            result = dns_utils.resolve_hostname("absent.example")
        self.assertEqual(result["status"], "nxdomain")
        self.assertEqual(factory.return_value.resolve.call_count, 1)
        self.assertEqual(result["errors"], {})

    def test_dns_timeout_remains_unknown(self):
        with patch("modules.dns_utils.dns.resolver.Resolver") as factory:
            factory.return_value.resolve.side_effect = dns.exception.Timeout()
            result = dns_utils.resolve_hostname("timeout.example")
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["errors"])
        self.assertEqual(result["all"], [])

    def test_ipv6_only_tenant_can_resolve(self):
        def resolve(hostname, qtype):
            if qtype == "AAAA":
                return ["2001:db8::1"]
            raise dns.resolver.NoAnswer()
        with patch("modules.dns_utils.dns.resolver.Resolver") as factory:
            factory.return_value.resolve.side_effect = resolve
            result = dns_utils.resolve_hostname("ipv6.example")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["all"], ["2001:db8::1"])


@unittest.skipUnless(DEPENDENCIES, "Provider-mode tests require requirements.txt")
class ProviderCatalogTests(unittest.TestCase):
    def test_custom_catalog_is_used_for_single_and_batch_scans(self):
        def check(provider, template, name, timeout):
            return {"provider": provider, "hostname": template.replace("SHORT_NAME", name),
                    "status": "no_record", "message": "fixture", "dns_result": None,
                    "web_check": dns_utils.empty_web_check()}
        with tempfile.TemporaryDirectory() as folder:
            catalog = Path(folder) / "providers.yaml"
            catalog.write_text("Fixture Provider: SHORT_NAME.fixture.example\n")
            batch = Path(folder) / "companies.txt"
            batch.write_text("acme\n")
            for args in (["-i", "acme", "-j"], ["-b", str(batch)]):
                with self.subTest(args=args), patch("saas_enum.dns_check", side_effect=check) as lookup, \
                     contextlib.redirect_stdout(io.StringIO()):
                    saas_enum.main([*args, "--yaml", str(catalog), "--providers", "fixture provider"])
                self.assertEqual(lookup.call_count, 1)
                self.assertEqual(lookup.call_args.args[:3], ("Fixture Provider", "SHORT_NAME.fixture.example", "acme"))

    def test_unknown_or_empty_provider_selection_never_scans_all(self):
        for selected in ("does-not-exist", ""):
            with self.subTest(selected=selected), patch("saas_enum.dns_check") as lookup, \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                saas_enum.main(["-i", "acme", "--providers", selected])
            self.assertEqual(caught.exception.code, 2)
            lookup.assert_not_called()

    def test_missing_catalog_is_not_silently_replaced_with_sample(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "missing.yaml"
            with self.assertRaises(FileNotFoundError):
                dns_utils.load_dns_integrations(path)
            self.assertFalse(path.exists())

    def test_default_catalog_is_independent_of_working_directory(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as folder:
            try:
                os.chdir(folder)
                catalog = dns_utils.load_dns_integrations()
                self.assertFalse(Path("dns_integrations.yaml").exists())
            finally:
                os.chdir(original)
        self.assertIn("Salesforce", catalog)


if __name__ == "__main__":
    unittest.main()
