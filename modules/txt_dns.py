"""TXT-only DNS collection using public DNS-over-HTTPS (standard library only)."""

import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

RESOLVERS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_domain(value):
    value = value.strip().rstrip(".").lower()
    if not value or ":" in value or "/" in value or "@" in value:
        raise ValueError(f"Expected a bare domain, got {value!r}")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain") from exc
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Use a domain, not an IP address")
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", x)
        for x in labels
    ):
        raise ValueError(f"Invalid domain: {value!r}")
    return value


def decode_txt(value):
    """Join DNS presentation-format character strings; accept Google's raw text.

    DNS escapes use decimal octets, not JSON/octal escapes. Separate RRs are
    NEVER concatenated. Malformed quoted RDATA is an error, not a partial match.
    """
    if not isinstance(value, str):
        raise ValueError("TXT data must be text")
    if not value.startswith('"'):
        return value
    result = bytearray()
    i = 0
    while i < len(value):
        while i < len(value) and value[i].isspace():
            i += 1
        if i == len(value):
            break
        if value[i] != '"':
            raise ValueError("Invalid TXT character string")
        i += 1
        while i < len(value) and value[i] != '"':
            if value[i] == "\\":
                i += 1
                if i >= len(value):
                    raise ValueError("Unterminated TXT escape")
                if len(value[i:i + 3]) == 3 and value[i:i + 3].isdigit():
                    octet = int(value[i:i + 3])
                    if octet > 255:
                        raise ValueError("Invalid TXT octet")
                    result.append(octet)
                    i += 3
                    continue
            result.extend(value[i].encode("utf-8"))
            i += 1
        if i == len(value):
            raise ValueError("Unterminated TXT character string")
        i += 1
    return result.decode("utf-8", errors="replace")


def parse_response(name, payload, resolver, source_url, fetched_at=None):
    if not isinstance(payload, dict) or type(payload.get("Status")) is not int:
        raise ValueError("Invalid DNS JSON: missing numeric Status")
    result = {
        "query_name": name, "record_type": "TXT", "resolver": resolver,
        "source_url": source_url, "fetched_at": fetched_at or utcnow(),
        "status": "ok", "rcode": payload["Status"],
        "dnssec_authenticated": bool(payload.get("AD", False)), "records": [],
    }
    if payload.get("TC"):
        result.update(status="truncated", error="Resolver returned a truncated answer")
        return result
    if payload["Status"] != 0:
        result["status"] = {2: "servfail", 3: "nxdomain", 5: "refused"}.get(
            payload["Status"], "dns_error")
        return result
    # Accept TXT only at the requested owner or at a returned CNAME-chain target.
    answers = payload.get("Answer", [])
    if not isinstance(answers, list) or any(not isinstance(a, dict) for a in answers):
        raise ValueError("Invalid DNS JSON: Answer must be a list of records")
    for answer in answers:
        if not isinstance(answer.get("name", ""), str):
            raise ValueError("Invalid DNS JSON: record owner must be text")
        if answer.get("type") in (5, 16) and not isinstance(answer.get("data"), str):
            raise ValueError("Invalid DNS JSON: CNAME/TXT data must be text")
    allowed = {name.lower().rstrip(".")}
    for _ in range(16):
        targets = {a["data"].lower().rstrip(".") for a in answers
                   if a.get("type") == 5 and a.get("name", "").lower().rstrip(".") in allowed}
        if targets <= allowed:
            break
        allowed.update(targets)
    seen = set()
    for answer in answers:
        owner = answer.get("name", "").lower().rstrip(".")
        if answer.get("type") != 16 or owner not in allowed:
            continue
        value = decode_txt(answer["data"])
        if (owner, value) not in seen:
            result["records"].append({"owner": owner, "value": value,
                                      "raw": answer["data"], "ttl": answer.get("TTL")})
            seen.add((owner, value))
    if not result["records"]:
        result["status"] = "no_data"
    return result


class TXTResolver:
    def __init__(self, resolver="google", timeout=10, rate=5, retries=1):
        self.resolver = resolver
        self.timeout = timeout
        self.interval = 1 / rate
        self.retries = retries
        self._lock = threading.Lock()
        self._next = 0.0

    def _throttle(self):
        with self._lock:
            now = time.monotonic()
            delay = max(0, self._next - now)
            self._next = max(now, self._next) + self.interval
        if delay:
            time.sleep(delay)

    def query(self, name):
        name = normalize_domain(name)
        url = RESOLVERS[self.resolver] + "?" + urllib.parse.urlencode(
            {"name": name, "type": "TXT"})
        request = urllib.request.Request(url, headers={
            "Accept": "application/dns-json", "User-Agent": "saas-enum-txt/1.0"})
        error = None
        for attempt in range(self.retries + 1):
            self._throttle()
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = json.load(response)
                result = parse_response(name, payload, self.resolver, url)
                if result["status"] != "servfail" or attempt == self.retries:
                    return result
            except (OSError, ValueError, KeyError, TypeError) as exc:
                error = f"{type(exc).__name__}: {exc}"
            if attempt < self.retries:
                time.sleep(0.25 * (attempt + 1))
        return {"query_name": name, "record_type": "TXT", "resolver": self.resolver,
                "source_url": url, "fetched_at": utcnow(), "status": "error",
                "rcode": None, "records": [], "error": error}
