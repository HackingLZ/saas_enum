"""Collect page evidence without treating generic login flows as tenant proof."""

import hashlib
import re
from typing import List, Tuple
from urllib.parse import unquote, urlparse

import requests
from bs4 import BeautifulSoup


def clean_text_for_search(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().lower()


def name_pattern(short_name: str):
    # A short company name must not match a substring of another company name.
    return re.compile(r"(?<![\w-])" + re.escape(short_name) + r"(?![\w-])", re.I)


def visible_reference(text: str, short_name: str) -> bool:
    # An echoed URL/hostname is not independent evidence in page content.
    text = re.sub(r"https?://\S+|\b[\w-]+(?:\.[\w-]+)+(?::\d+)?(?:/\S*)?", " ", text, flags=re.I)
    return bool(short_name and name_pattern(short_name).search(text))


def extract_contextual_snippets(text: str, search_term: str, context_chars: int = 100) -> List[str]:
    if not text or not search_term:
        return []
    snippets = []
    for match in name_pattern(search_term).finditer(text):
        start, end = max(0, match.start() - context_chars), min(len(text), match.end() + context_chars)
        snippet = re.sub(r"\s+", " ", text[start:end]).strip()
        snippets.append(("..." if start else "") + snippet + ("..." if end < len(text) else ""))
        if len(snippets) == 5:
            break
    return snippets


def analyze_webpage_content(short_name: str, soup: BeautifulSoup, page_text: str,
                            final_url: str, result: dict) -> Tuple[bool, List[str], str]:
    evidence = []
    short_name = short_name.strip().lower()
    web = result["web_check"]
    if not short_name:
        web["evidence"] = []
        return False, [], "none"
    parsed = urlparse(final_url)
    hostname = (parsed.hostname or "").lower()
    authentication_flow = bool(re.search(
        r"(?:^|[./_-])(?:sso|saml2?|oauth2?|openid|login|signin|sign-in|single-sign-on)(?:$|[./_-])",
        hostname + unquote(parsed.path), re.I))
    web["authentication_flow"] = authentication_flow
    if authentication_flow:
        evidence.append("Authentication/login flow observed; this alone does not identify a tenant")

    url_reference = short_name in hostname.split(".") or bool(name_pattern(short_name).search(unquote(parsed.path)))
    if url_reference:
        evidence.append("Tenant name in URL; not independent confirmation")

    content_reference = False
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    if visible_reference(title, short_name):
        content_reference = True
        evidence.append("Standalone company name in page title")
    if visible_reference(page_text, short_name):
        content_reference = True
        evidence.append("Standalone company name in visible page text")
    for meta in soup.find_all("meta"):
        if str(meta.get("name", meta.get("property", ""))).lower() in {"description", "og:title", "og:description"}:
            if visible_reference(str(meta.get("content", "")), short_name):
                content_reference = True
                evidence.append("Company name in page description")
                break
    for img in soup.find_all("img"):
        if visible_reference(str(img.get("alt", "")), short_name):
            content_reference = True
            evidence.append("Company name in image description")
            break

    # URL-bearing attributes and form actions often echo any requested tenant.
    for tag, attr in [("form", "action"), ("img", "src")]:
        if any(name_pattern(short_name).search(str(node.get(attr, ""))) for node in soup.find_all(tag)):
            url_reference = True
            evidence.append("Tenant name in a link or asset URL; not independent confirmation")
            break

    normalized = clean_text_for_search(page_text)
    negative = re.search(
        r"\b(?:page not found|does not exist|doesn't exist|no such (?:tenant|organization|account)|"
        r"coming soon|under construction|temporarily unavailable)\b|"
        r"\b(?:tenant|organization|workspace|company|site|subdomain|account)\b.{0,80}\b(?:not found|not available|unknown|invalid)\b|"
        r"\b(?:unknown|invalid|unrecognized)\s+(?:tenant|organization|workspace|company|subdomain)\b",
        normalized)
    web["negative_evidence"] = bool(negative)
    if negative:
        evidence.append("Missing-tenant/error/placeholder page; no positive attribution")
    web["evidence"] = evidence
    if negative:
        return False, evidence, "none"
    if content_reference:
        return True, evidence, "strong"
    if url_reference:
        return True, evidence, "weak"
    return False, evidence, "none"


def check_webpage_content(url: str, short_name: str, result: dict,
                          timeout: float = 10) -> Tuple[bool, str, str, str]:
    web = result["web_check"]
    web.update(performed=True, url_checked=url, http_status=None, request_error=None)
    try:
        with requests.get(url, headers={"User-Agent": "saas-enum/1.0", "Accept": "text/html,application/xhtml+xml"},
                          timeout=timeout, allow_redirects=True, verify=True) as response:
            final_url = response.url
            web.update(final_url=final_url, http_status=response.status_code,
                       redirect_chain=[{"url": r.url, "status": r.status_code} for r in response.history])
            if response.status_code != 200:
                return False, f"HTTP {response.status_code}; no positive page evidence", final_url, "none"
            soup = BeautifulSoup(response.text, "html.parser")
        for element in soup(["script", "style", "noscript"]):
            element.decompose()
        page_text = soup.get_text(" ", strip=True)
        # Mask the supplied tenant when comparing templates against a random control.
        normalized = name_pattern(short_name).sub("<tenant>", clean_text_for_search(page_text))
        web["page_fingerprint"] = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        reference_found, evidence, strength = analyze_webpage_content(short_name, soup, page_text, final_url, result)
        web.update(page_title=soup.title.get_text(" ", strip=True) if soup.title else None,
                   text_snippets=extract_contextual_snippets(page_text, short_name),
                   match_strength=strength, reference_found=reference_found,
                   has_forms=bool(soup.find_all("form")), word_count=len(page_text.split()),
                   html_excerpt=str(soup)[:1500])
        return reference_found, " | ".join(evidence[:5]) or "No tenant-specific indicators found", final_url, strength
    except requests.RequestException as exc:
        web["request_error"] = f"{type(exc).__name__}: {exc}"
        return False, f"Request failed: {type(exc).__name__}; no positive page evidence", url, "none"
