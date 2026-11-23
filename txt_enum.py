#!/usr/bin/env python3
"""Infer vendor associations from TXT records; Python 3.10+, no dependencies."""

import argparse
import concurrent.futures
import csv
import io
import json
import math
import sqlite3
import sys
from collections import deque
from pathlib import Path

from modules.txt_dns import TXTResolver, normalize_domain, parse_response, utcnow
from modules.txt_matcher import DEFAULT_RULES, analyze, catalog_digest, discover, load_rules, spf_references
from modules.txt_storage import save_database, summary

ERROR_STATUSES = {"error", "servfail", "refused", "dns_error", "truncated", "unavailable"}


def scan_domain(domain, resolver, catalog, dmarc=True, spf_depth=1, max_queries=12):
    queries, warnings = [], []
    pending = deque([(domain, "apex", 0, [])])
    if dmarc:
        pending.append(("_dmarc." + domain, "dmarc", 0, []))
    seen = {name for name, _, _, _ in pending}
    while pending:
        if len(queries) >= max_queries:
            warnings.append(f"Query budget ({max_queries}) reached; SPF expansion incomplete")
            break
        name, scope, depth, via = pending.popleft()
        query = resolver.query(name)
        query.update(scope=scope, via=via)
        queries.append(query)
        if scope == "dmarc" or query["status"] != "ok":
            continue
        spf_records = [r for r in query["records"] if r["value"].lower().split()[:1] == ["v=spf1"]]
        if len(spf_records) > 1:
            warnings.append(f"Multiple SPF records at {name}; references are not a validated SPF policy")
        for record in spf_records:
            for ref in spf_references(record["value"]):
                target = ref["domain"]
                if target in seen:
                    continue
                if depth >= spf_depth:
                    if spf_depth:
                        warnings.append(f"SPF depth limit at {name} -> {target}")
                    continue
                if "%" in target:
                    warnings.append(f"SPF macro not expanded: {target}")
                    continue
                try:
                    target = normalize_domain(target)
                except ValueError:
                    warnings.append(f"Invalid SPF target skipped: {target}")
                    continue
                seen.add(target)
                pending.append((target, "spf", depth + 1, via + [name]))
    status = queries[0]["status"]
    if status in ERROR_STATUSES:
        status = "error"
    elif any(q["status"] in ERROR_STATUSES for q in queries[1:]) or warnings:
        status = "partial"
    elif status == "no_data" and any(q["records"] for q in queries):
        status = "ok"
    result = {"schema_version": 1, "domain": domain, "collected_at": utcnow(),
              "collection_method": "live_doh", "status": status,
              "queries": queries, "warnings": sorted(set(warnings))}
    return analyze(result, catalog)


def import_web(path, catalog, live=False):
    results = []
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        domain = normalize_domain(item["domain"])
        if live and item.get('extracted_records'):
            raise ValueError('Live DNS imports require DNS JSON responses, not extracted web tables')
        if item.get("extracted_records"):
            records, seen = [], set()
            for record in item["extracted_records"]:
                if record["owner"].rstrip(".").lower() != domain:
                    raise ValueError(f"Wrong TXT owner in snapshot line {number}")
                if record["value"] not in seen:
                    records.append(record)
                    seen.add(record["value"])
            query = {"query_name": domain, "record_type": "TXT",
                     "resolver": item.get("provider", "third_party_dns_snapshot"),
                     "source_url": item["source_url"], "fetched_at": item["retrieved_at"],
                     "status": "ok", "rcode": None, "records": records,
                     "source_format": "extracted_dns_table", "crawl_label": item.get("crawl_label"),
                     "source_observed_at": item.get("source_observed_at"),
                     "source_table_end_observed": item.get("source_table_end_observed", False)}
        elif item.get("payload"):
            query = parse_response(domain, item["payload"], item.get('provider', 'google') if live else "google_via_web_snapshot",
                                   item["source_url"], item["retrieved_at"])
        else:
            query = {"query_name": domain, "record_type": "TXT", "resolver": "google_via_web_snapshot",
                     "source_url": item["source_url"], "fetched_at": item["retrieved_at"],
                     "status": "unavailable", "rcode": None, "records": [],
                     "error": "Web tool did not return a usable DNS response; DNS state is unknown"}
        if live:
            query['transport'] = item.get('transport', 'imported_doh_json')
            if not item.get('payload'):
                query.update(resolver=item.get('provider', 'google'),
                             error=item.get('error', 'DNS collection failed; state is unknown'))
        query.update(scope="apex", via=[])
        result = {"schema_version": 1, "domain": domain, "collected_at": item["retrieved_at"],
                  "collection_method": "live_doh_import" if live else "web_tool_snapshot", "queries": [query],
                  "status": "error" if query["status"] in ERROR_STATUSES else query["status"],
                  "source_attempts": item.get("attempts", []),
                  "warnings": (["Live recursive resolver response; DNS TTL caching still applies."] if live else
                               ["May be cached by the web tool; authoritative query time unknown."]) +
                               ["Apex TXT only; DMARC and recursive SPF were not collected."]}
        if item.get("extracted_records"):
            result["warnings"].append("Third-party DNS table: record completeness and TTLs are not independently verified.")
        results.append(analyze(result, catalog))
    return results


def read_replay(path, catalog):
    content = Path(path).read_text()
    # Both full JSON reports and JSONL raw-output are replayable offline.
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        results = [json.loads(line) for line in content.splitlines() if line.strip()]
    else:
        if isinstance(parsed, dict) and "results" in parsed:
            results = parsed["results"]
        elif isinstance(parsed, list):
            results = parsed
        else:
            results = [parsed]
    for result in results:
        if result.get("schema_version") != 1 or "queries" not in result:
            raise ValueError("Replay needs scan JSON/JSONL; use --import-web for web snapshots")
    return [analyze(result, catalog) for result in results]


def write_text(path, content):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")


def safe_csv(value):
    # Evidence is untrusted text; do not turn TXT strings into spreadsheet formulas.
    text = str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def render(results, metadata, fmt):
    if fmt == "json":
        return json.dumps({"metadata": metadata, "summary": summary(results), "results": results}, indent=2) + "\n"
    if fmt == "csv":
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow(["domain", "status", "service", "category", "confidence", "signal", "query_name",
                         "value", "rule_id", "via", "fetched_at", "collection_method", "association"])
        for result in results:
            for match in result["matches"]:
                writer.writerow([safe_csv(v) for v in [result["domain"], result["status"],
                    match["service"], match["category"], match["confidence"], match["signal"],
                    match["query_name"], match["value"], match["rule_id"], " -> ".join(match["via"]),
                    match["fetched_at"], result["collection_method"], match["association"]]])
            if not result["matches"]:
                writer.writerow([safe_csv(v) for v in [result["domain"], result["status"], "", "", "", "", "", "", "", "",
                                 result["collected_at"], result["collection_method"], ""]])
        return buffer.getvalue()
    lines = ["TXT vendor associations (not proof of active use)"]
    for result in results:
        lines.append(f"\n{result['domain']} [{result['status']}; {result['collection_method']}]")
        for service in result["services"]:
            association = "inherited via SPF" if service.get("association") == "inherited" else "direct DNS reference"
            lines.append(f"  {service['service']} | {service['confidence']} | {association} | {', '.join(service['signals'])} | {service['evidence_count']} evidence")
        if not result["services"]:
            lines.append("  No service matches; see query status before interpreting this result.")
        lines.extend(f"  Note: {warning}" for warning in result["warnings"])
        lines.extend(f"  {q['query_name']}: {q['status']} {q.get('error', '')}" for q in result["queries"] if q["status"] in ERROR_STATUSES)
    lines.append("\n" + json.dumps(summary(results)))
    return "\n".join(lines) + "\n"


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-d", "--domain", "-i", "--input", action="append", help="Bare domain (repeatable)")
    source.add_argument("-b", "--batch", help="Domains file, one per line; # comments allowed")
    source.add_argument("--replay", help="Re-match saved JSON/JSONL offline")
    source.add_argument("--import-web", help="Import research web DNS JSONL snapshots offline")
    source.add_argument("--import-dns", help="Import live-collected DNS JSONL responses offline")
    source.add_argument("--list-services", action="store_true", help="List services in the fingerprint catalog")
    parser.add_argument("--fingerprints", default=str(DEFAULT_RULES), help="Custom JSON fingerprint catalog")
    parser.add_argument("-o", "--output", help="Report destination (stdout otherwise)")
    parser.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text")
    parser.add_argument("-j", "--json", action="store_true", help="Alias for --format json")
    parser.add_argument("--raw-output", help="Save replayable scan JSONL with evidence")
    parser.add_argument("--db", help="Append a scan to a SQLite database")
    parser.add_argument("--unknowns", help="Write grouped unknown patterns as JSON for Codex review")
    parser.add_argument("--resolver", choices=["google", "cloudflare"], default="google")
    parser.add_argument("-w", "--workers", type=positive_int, default=5)
    parser.add_argument("--rate", type=positive_float, default=5, help="Global DNS requests/second (default 5)")
    parser.add_argument("-t", "--timeout", type=positive_float, default=10)
    parser.add_argument("--retries", type=int, choices=range(4), default=1)
    parser.add_argument("--spf-depth", type=int, choices=range(6), default=1,
                        help="SPF include/redirect depth; 0 disables expansion (default 1)")
    parser.add_argument("--max-queries", type=positive_int, default=12, help="Query budget per domain (default 12)")
    parser.add_argument("--apex-only", action="store_true", help="Only the input name: no DMARC or SPF expansion")
    parser.add_argument("--strict", action="store_true", help="Exit 1 for any incomplete/error result")
    args = parser.parse_args(argv)
    try:
        catalog = load_rules(args.fingerprints)
        if args.list_services:
            for name in sorted({r["service"] for r in catalog["rules"]}):
                print(name)
            return 0
        output_paths = [Path(p).resolve() for p in (args.output, args.raw_output, args.db, args.unknowns) if p]
        input_paths = {Path(p).resolve() for p in (args.batch, args.replay, args.import_web, args.import_dns, args.fingerprints) if p}
        if len(output_paths) != len(set(output_paths)) or set(output_paths) & input_paths:
            raise ValueError("Output paths must be distinct and must not overwrite inputs")
        if args.replay:
            results = read_replay(args.replay, catalog)
        elif args.import_web:
            results = import_web(args.import_web, catalog)
        elif args.import_dns:
            results = import_web(args.import_dns, catalog, live=True)
        else:
            values = args.domain or [line.split("#", 1)[0].strip()
                                     for line in Path(args.batch).read_text().splitlines()]
            domains = sorted({normalize_domain(d) for d in values if d})
            if not domains:
                raise ValueError("No domains to scan")
            resolver = TXTResolver(args.resolver, args.timeout, args.rate, args.retries)
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {pool.submit(scan_domain, d, resolver, catalog, not args.apex_only,
                                       0 if args.apex_only else args.spf_depth,
                                       args.max_queries): d for d in domains}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    results.append(result)
                    print(f"[{len(results)}/{len(domains)}] {result['domain']}: "
                          f"{len(result['services'])} services ({result['status']})", file=sys.stderr)
        if not results:
            raise ValueError("No results to analyze")
        domains = [r["domain"] for r in results]
        if len(domains) != len(set(domains)):
            raise ValueError("Duplicate domain in replay/import; use one snapshot per domain per run")
        results.sort(key=lambda r: r["domain"])
        metadata = {"schema_version": 1, "created_at": utcnow(), "catalog_version": catalog["version"],
                    "catalog_sha256": catalog_digest(catalog),
                    "collection_methods": sorted({r["collection_method"] for r in results}),
                    "interpretation": "Confidence is vendor attribution, not proof of active service use.",
                    "options": {"resolver": args.resolver, "rate": args.rate, "timeout": args.timeout,
                                "spf_depth": 0 if args.apex_only else args.spf_depth,
                                "max_queries": args.max_queries, "apex_only": args.apex_only,
                                "offline": bool(args.replay or args.import_web or args.import_dns)}}
        if args.raw_output:
            write_text(args.raw_output, "".join(json.dumps(r) + "\n" for r in results))
        if args.unknowns:
            write_text(args.unknowns, json.dumps({"metadata": metadata, "candidates": discover(results)}, indent=2) + "\n")
        if args.db:
            metadata["database_run_id"] = save_database(args.db, results, metadata)
        report = render(results, metadata, "json" if args.json else args.format)
        if args.output:
            write_text(args.output, report)
            print(json.dumps(summary(results)), file=sys.stderr)
        else:
            print(report, end="")
        failed = sum(r["status"] in ("error", "partial") for r in results)
        return int(all(r["status"] == "error" for r in results) or (args.strict and failed > 0))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        parser.exit(2, f"error: {exc}\n")
    except KeyboardInterrupt:
        parser.exit(130, "Interrupted.\n")


if __name__ == "__main__":
    raise SystemExit(main())
