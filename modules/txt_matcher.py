"""Evidence-preserving matching; no network or model calls."""

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "catalogs" / "txt_fingerprints.json"


def load_rules(path=DEFAULT_RULES):
    catalog = json.loads(Path(path).read_text())
    if catalog.get("schema_version") != 1 or not isinstance(catalog.get("rules"), list):
        raise ValueError("Unsupported fingerprint catalog schema")
    seen = set()
    for rule in catalog["rules"]:
        for field in ("id", "service", "category", "kind", "confidence", "basis"):
            if not rule.get(field):
                raise ValueError(f"Fingerprint missing {field}")
        sources = rule.get("sources")
        if not isinstance(sources, list) or any(not isinstance(s, str) or not s.strip() for s in sources):
            raise ValueError("Fingerprint sources must be a list of nonempty strings")
        if not sources and not (rule["confidence"] == "medium" and
                                rule.get("observation_sources_withheld") is True):
            raise ValueError("Fingerprint missing sources; only inferred rules may withhold observation sources")
        if rule["id"] in seen:
            raise ValueError(f"Duplicate fingerprint: {rule['id']}")
        seen.add(rule["id"])
        if rule["confidence"] not in ("high", "medium"):
            raise ValueError("Confidence must be high or medium")
        if rule["kind"] == "txt_regex":
            if not rule.get("pattern", "").startswith("^"):
                raise ValueError("TXT patterns must be anchored")
            re.compile(rule["pattern"], re.I)
        elif rule["kind"] in ("spf_domain", "dmarc_domain"):
            if not rule.get("domains"):
                raise ValueError("Domain rule missing domains")
        else:
            raise ValueError(f"Unknown rule kind: {rule['kind']}")
    return catalog


def catalog_digest(catalog):
    return hashlib.sha256(json.dumps(catalog, sort_keys=True).encode()).hexdigest()


def spf_references(value):
    if not re.match(r"^v=spf1(?:\s|$)", value, re.I):
        return []
    refs = []
    for token in value.split()[1:]:
        match = re.fullmatch(r"([+?~-]?)(include:|redirect=)([^\s]+)", token, re.I)
        if match:
            qualifier, mechanism, domain = match.groups()
            # Negative, neutral and softfail mechanisms do not authorize a sender.
            if qualifier not in ("", "+"):
                continue
            if mechanism.lower() == "redirect=" and qualifier:
                continue
            refs.append({"domain": domain.lower().rstrip("."),
                         "mechanism": mechanism.rstrip(":="), "token": token})
    return refs


def dmarc_destinations(value):
    if not re.match(r"^v=DMARC1(?:\s*;|$)", value, re.I):
        return []
    destinations = []
    for tag in value.split(";")[1:]:
        key, sep, val = tag.strip().partition("=")
        if not sep or key.lower() not in ("rua", "ruf"):
            continue
        for uri in val.split(","):
            parsed = urlsplit(uri.strip().split("!", 1)[0])
            if parsed.scheme.lower() == "mailto" and "@" in parsed.path:
                destinations.append(parsed.path.rsplit("@", 1)[1].lower().rstrip("."))
    return destinations


def domain_matches(target, pattern):
    pattern = pattern.lower().rstrip(".")
    return target == pattern or target.endswith("." + pattern)


def match_query(query, catalog):
    matches = []
    if query["status"] != "ok":
        return matches
    scope = query.get("scope", "apex")
    for index, record in enumerate(query["records"]):
        value = record["value"].strip()
        for rule in catalog["rules"]:
            evidence = []
            if rule["kind"] == "txt_regex" and scope == "apex":
                found = re.search(rule["pattern"], value, re.I)
                if found:
                    evidence = [found.group(0)]
            elif rule["kind"] == "spf_domain" and scope in ("apex", "spf"):
                evidence = [r["token"] for r in spf_references(value)
                            if any((r["domain"] == d.lower().rstrip('.') if rule.get('domains_exact') else
                                    domain_matches(r["domain"], d)) for d in rule["domains"])]
            elif rule["kind"] == "dmarc_domain" and scope == "dmarc":
                evidence = [d for d in dmarc_destinations(value)
                            if any(domain_matches(d, p) for p in rule["domains"])]
            for matched in dict.fromkeys(evidence):
                matches.append({
                    "rule_id": rule["id"], "service": rule["service"],
                    "category": rule["category"], "confidence": rule["confidence"],
                    "signal": {"txt_regex": "domain_verification", "spf_domain": "spf_reference",
                               "dmarc_domain": "dmarc_reporting"}[rule["kind"]],
                    "query_name": query["query_name"], "record_index": index,
                    "owner": record["owner"], "value": record["value"],
                    "matched": matched, "scope": scope,
                    "association": "inherited" if scope == "spf" else "direct",
                    "via": query.get("via", []), "fetched_at": query["fetched_at"],
                    "sources": rule["sources"], "basis": rule["basis"],
                    "observation_sources_withheld": rule.get("observation_sources_withheld", False),
                    "notes": rule.get("notes", ""),
                })
    return matches


def analyze(result, catalog):
    result = dict(result)
    result["catalog_sha256"] = catalog_digest(catalog)
    result["matches"] = [m for q in result["queries"] for m in match_query(q, catalog)]
    services = defaultdict(list)
    for match in result["matches"]:
        services[match["service"]].append(match)
    result["services"] = [{"service": name, "category": ms[0]["category"],
                           "confidence": "high" if any(m["confidence"] == "high" for m in ms) else "medium",
                           "signals": sorted({m["signal"] for m in ms}),
                           "association": "direct" if any(m["association"] == "direct" for m in ms) else "inherited",
                           "direct_evidence_count": sum(m["association"] == "direct" for m in ms),
                           "inherited_evidence_count": sum(m["association"] == "inherited" for m in ms),
                           "evidence_count": len(ms)} for name, ms in sorted(services.items())]
    return result


def discover(results):
    """Group unknown prefixes/references, never promote guesses to signatures."""
    groups = {}
    for result in results:
        known = {(m["query_name"], m["record_index"]) for m in result["matches"]}
        matched_tokens = {(m["query_name"], m["record_index"], m["matched"])
                          for m in result["matches"]}
        for query in result["queries"]:
            for index, record in enumerate(query["records"]):
                value = record["value"].strip()
                refs = spf_references(value)
                if re.match(r"^v=spf1(?:\s|$)", value, re.I):
                    keys = [("spf_include", r["domain"]) for r in refs
                            if (query["query_name"], index, r["token"]) not in matched_tokens]
                elif (query["query_name"], index) in known:
                    continue
                else:
                    prefix = re.match(r"^([A-Za-z_][A-Za-z0-9_.-]{1,100})\s*[=:]", value)
                    # A base64 token ending in '=' or '==' is not a key/value marker.
                    if prefix and not value[prefix.end():].strip('= \t'):
                        prefix = None
                    if prefix:
                        key = re.sub(r"(-domain-verification)-[a-z0-9]+$", r"\1-<tenant>", prefix[1], flags=re.I)
                        key = re.sub(r"^(pardot|sending_domain)[0-9]+$", r"\1<account-id>", key, flags=re.I)
                        keys = [("txt_prefix", key.lower())]
                    else:
                        marker = re.fullmatch(r"([A-Za-z][A-Za-z0-9_.-]*?(?:verification|validation|verify|confirmation))([_-])[A-Za-z0-9_-]{6,}", value, re.I)
                        suffix = re.fullmatch(r"[A-Za-z0-9_-]+\.(\_[A-Za-z][A-Za-z0-9_-]+)", value)
                        if marker:
                            keys = [("txt_marker", marker[1].lower() + marker[2] + '<token>')]
                        elif suffix:
                            keys = [("txt_suffix", suffix[1].lower())]
                        else:
                            keys = [("opaque", "unattributed-token")]
                for kind, key in keys:
                    group = groups.setdefault((kind, key), {"kind": kind, "pattern": key,
                                              "domains": set(), "record_count": 0, "examples": []})
                    group["domains"].add(result["domain"])
                    group["record_count"] += 1
                    if len(group["examples"]) < 3:
                        group["examples"].append({"domain": result["domain"],
                                                  "query_name": query["query_name"], "value": value})
    output = []
    for group in groups.values():
        group["domains"] = sorted(group["domains"])
        group["domain_count"] = len(group["domains"])
        group["review_status"] = "unreviewed"
        output.append(group)
    return sorted(output, key=lambda g: (-g["domain_count"], g["kind"], g["pattern"]))
