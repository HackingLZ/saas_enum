import concurrent.futures
import dns.exception
import dns.resolver
import random
import string
from pathlib import Path
from urllib.parse import unquote, urlparse
import yaml
import time
import logging
from typing import Dict, Any

from .reporting import console
from .web_analysis import check_webpage_content
from .txt_dns import normalize_domain

logger = logging.getLogger(__name__)


DEFAULT_INTEGRATIONS = Path(__file__).resolve().parent.parent / "dns_integrations.yaml"


def load_dns_integrations(yaml_path=None) -> Dict[str, str]:
    """Load validated patterns; missing input must never create a sample catalog."""
    path = Path(yaml_path) if yaml_path is not None else DEFAULT_INTEGRATIONS
    with path.open(encoding="utf-8") as stream:
        integrations = yaml.safe_load(stream)
    if not isinstance(integrations, dict) or not integrations:
        raise ValueError("Provider YAML must be a nonempty mapping of names to hostname templates")
    for provider, template in integrations.items():
        if not isinstance(provider, str) or not provider.strip() or not isinstance(template, str):
            raise ValueError("Provider names and hostname templates must be nonempty strings")
        if template.count("SHORT_NAME") != 1:
            raise ValueError(f"Provider {provider!r} needs exactly one SHORT_NAME placeholder")
        normalize_domain(template.replace("SHORT_NAME", "example"))
    return integrations


def generate_random_subdomain(length: int = 12) -> str:
    """Generate a random subdomain for comparison testing."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def resolve_hostname(hostname: str, timeout: float = 5) -> Dict[str, Any]:
    """Preserve DNS failures separately from absent records within a shared budget."""
    records, statuses, errors = {}, {}, {}
    deadline = time.monotonic() + timeout
    nxdomain = False
    for qtype in ("A", "AAAA", "CNAME", "MX", "TXT"):
        records[qtype] = []
        remaining = deadline - time.monotonic()
        if nxdomain:
            statuses[qtype] = "nxdomain"
            continue
        if remaining <= 0:
            statuses[qtype] = "timeout"
            errors[qtype] = "DNS time budget exhausted"
            continue
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = remaining
            resolver.lifetime = remaining
            records[qtype] = sorted(str(item) for item in resolver.resolve(hostname, qtype))
            statuses[qtype] = "ok" if records[qtype] else "no_data"
        except dns.resolver.NXDOMAIN:
            nxdomain = True
            statuses[qtype] = "nxdomain"
        except dns.resolver.NoAnswer:
            statuses[qtype] = "no_data"
        except dns.exception.Timeout as exc:
            statuses[qtype] = "timeout"
            errors[qtype] = str(exc)
        except (dns.exception.DNSException, OSError) as exc:
            statuses[qtype] = "error"
            errors[qtype] = f"{type(exc).__name__}: {exc}"
    combined = [value for values in records.values() for value in values]
    status = ("partial" if combined else "error") if errors else (
        "ok" if combined else "nxdomain" if nxdomain else "no_data")
    return {"all": combined, "details": records, "status": status,
            "query_statuses": statuses, "errors": errors}


def empty_web_check():
    return {"performed": False, "url_checked": None, "final_url": None,
            "reference_found": False, "details": None, "text_snippets": [],
            "page_title": None, "html_excerpt": None, "has_forms": False,
            "word_count": 0, "evidence": [], "match_strength": "none",
            "http_status": None, "request_error": None}


def compare_control(candidate, control):
    """Return whether a random tenant reproduces the supposed positive evidence."""
    if control.get("request_error") or control.get("http_status") is None:
        return "inconclusive"
    if control["http_status"] in (404, 410):
        return "different"
    if control["http_status"] != 200:
        return "inconclusive"
    if candidate.get("page_fingerprint") and candidate["page_fingerprint"] == control.get("page_fingerprint"):
        return "shared_page"
    def destination(url):
        parsed = urlparse(url or "")
        # OAuth state, return URLs, and echoed tenant names in queries are not proof.
        return (parsed.hostname or "").lower(), unquote(parsed.path).rstrip("/").lower()
    if (candidate.get("authentication_flow") or control.get("authentication_flow")) and (
            destination(candidate.get("final_url")) == destination(control.get("final_url"))):
        return "shared_login"
    if control.get("match_strength") == "strong":
        return "reflected_name"
    return "different"


def dns_check(provider: str, domain_template: str, short_name: str, timeout: float = 10) -> Dict[str, Any]:
    """Compare a candidate tenant with a randomized control before corroboration."""
    deadline = time.monotonic() + timeout
    random_name = generate_random_subdomain(16)
    fake_hostname = domain_template.replace("SHORT_NAME", random_name)
    real_hostname = domain_template.replace("SHORT_NAME", short_name)
    result = {"provider": provider, "hostname": real_hostname, "status": "",
              "message": "", "dns_result": None, "web_check": empty_web_check(),
              "control_check": {"hostname": fake_hostname, "dns_result": None,
                                "web_check": empty_web_check(), "verdict": "not_checked"},
              "association": "candidate", "active_use_verified": False}
    dns_timeout = min(3, timeout * 0.25)
    real = resolve_hostname(real_hostname, timeout=dns_timeout)
    result["dns_result"] = real
    if not real["all"]:
        failed = real.get("status") == "error"
        result.update(status="error" if failed else "no_record",
                      message="DNS lookup failed; tenant existence is unknown." if failed else "No DNS records found.")
        return result
    fake = resolve_hostname(fake_hostname, timeout=dns_timeout)
    result["control_check"]["dns_result"] = fake
    control_incomplete = fake.get("status") in ("error", "partial")
    # Wildcard backends can rotate IPs; different answers do not prove a tenant.
    wildcard = bool(fake["all"])
    result["wildcard_dns"] = wildcard if not control_incomplete else None
    result.update(status="wildcard_match" if wildcard else "valid_dns",
                  message="Random tenant also resolves; DNS alone cannot identify a tenant." if wildcard else
                          "DNS records found; active service use is not established.")
    if control_incomplete:
        result["control_check"]["verdict"] = "inconclusive"
    elif not wildcard:
        result["control_check"]["verdict"] = "no_control_dns"
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        result["web_check"]["details"] = "No time remaining for page comparison"
        return result
    web = result["web_check"]
    found, details, final_url, strength = check_webpage_content(
        f"https://{real_hostname}", short_name, result,
        timeout=min(8, remaining / (2 if wildcard else 1)))
    web.update(reference_found=found, details=details, final_url=final_url, match_strength=strength)
    if wildcard and web.get("http_status") == 200:
        remaining = deadline - time.monotonic()
        control = result["control_check"]["web_check"]
        if remaining > 0:
            control_result = {"web_check": control}
            cfound, cdetails, curl, cstrength = check_webpage_content(
                f"https://{fake_hostname}", random_name, control_result, timeout=min(8, remaining))
            control.update(reference_found=cfound, details=cdetails, final_url=curl, match_strength=cstrength)
            result["control_check"]["verdict"] = compare_control(web, control)
        else:
            result["control_check"]["verdict"] = "inconclusive"
    verdict = result["control_check"]["verdict"]
    if verdict in {"shared_page", "shared_login", "reflected_name"}:
        result.update(status="wildcard_match", message="Random tenant reproduces the page/login behavior; no tenant-specific confirmation.")
    elif found and strength == "strong":
        complete_dns = real.get("status", "ok") == "ok" and not control_incomplete
        if complete_dns and verdict in {"different", "no_control_dns"}:
            result.update(status="confirmed_via_web" if wildcard else "confirmed_valid", association="corroborated",
                          message="Company-specific page evidence differs from the random control; active use remains unverified.")
        else:
            result["message"] = "Company name found, but control checks are incomplete; association remains unconfirmed."
    elif found and strength == "weak" and not wildcard:
        result.update(status="url_only_match", message="Company name appears only in URL/link evidence; association remains unconfirmed.")
    elif not wildcard:
        result.update(status="dns_only_match", message="DNS records found without company-specific page evidence.")
    return result


def check_dns_providers(yaml_path=None):
    """Check all DNS providers for liveness"""
    DNS_INTEGRATIONS = load_dns_integrations(yaml_path)

    console.print(f"[bold]Checking {len(DNS_INTEGRATIONS)} DNS providers for liveness...[/bold]")

    results = []
    random_name = generate_random_subdomain()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for provider, domain_template in DNS_INTEGRATIONS.items():
            hostname = domain_template.replace("SHORT_NAME", random_name)
            futures[executor.submit(resolve_hostname, hostname)] = (provider, hostname)

        for future in concurrent.futures.as_completed(futures):
            provider, hostname = futures[future]
            try:
                dns_result = future.result()
                is_wildcard = True if dns_result["all"] else (
                    None if dns_result.get("status") in ("error", "partial") else False)
                results.append({
                    "provider": provider,
                    "hostname": hostname,
                    "is_wildcard": is_wildcard,
                    "dns_result": dns_result,
                })
            except Exception as e:
                logger.error(f"Error checking provider {provider}: {str(e)}")

    wildcard_count = sum(r["is_wildcard"] is True for r in results)
    unknown_count = sum(r["is_wildcard"] is None for r in results)

    from rich.table import Table

    table = Table(title="DNS Provider Wildcard Check Results")
    table.add_column("Provider", style="cyan")
    table.add_column("Test Hostname")
    table.add_column("Wildcard?", justify="center")

    for result in results:
        wildcard_text = {True: "YES", False: "NO", None: "UNKNOWN"}[result["is_wildcard"]]
        wildcard_style = {True: "red", False: "green", None: "yellow"}[result["is_wildcard"]]
        table.add_row(result["provider"], result["hostname"], f"[{wildcard_style}]{wildcard_text}[/{wildcard_style}]")

    console.print(table)
    console.print(f"\n[bold]Summary:[/bold] {wildcard_count} out of {len(results)} providers resolve a random tenant; {unknown_count} checks are inconclusive.")

    return results
