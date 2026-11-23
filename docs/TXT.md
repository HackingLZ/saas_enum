# TXT service discovery

Run from this checkout with Python 3.10 or newer. TXT mode uses only the standard
library. The legacy provider-subdomain/web mode still uses `requirements.txt`.

## Generate local databases

No databases, domain lists, or collected DNS snapshots are distributed. Generate
all databases yourself from the bundled generic catalog and your own inputs.

```bash
# Offline: create the optional SQLite rules catalog from the bundled JSON.
python3 scripts/build_catalog_db.py
# Choose a different output filename if a database already exists.
python3 scripts/build_catalog_db.py --output data/technology_map-new.sqlite
```

`data/technology_map.sqlite` contains detection rules, not scan results. The
lookup CLI reads `catalogs/txt_fingerprints.json` directly and does not require a
SQLite rules database. To use private rules, pass `--fingerprints data/my-rules.json`
to either command.

Create `data/companies.txt` yourself with one full domain per line, then use the
batch command below to generate `output/services.sqlite` and the report files.
The CLI creates output directories and the scan database automatically. Keep
inputs in `data/` and outputs in `output/`; both directories are ignored by Git.

## Commands

```bash
# Same TXT implementation, either entry point
python3 txt_enum.py --domain example.com
python3 saas_enum.py --txt -i example.com

# Exactly one TXT query per input domain
python3 txt_enum.py --domain example.com --apex-only

# Repeat --domain, or use a file (blank lines and # comments are supported)
python3 txt_enum.py --domain example.com --domain example.org --format json
python3 txt_enum.py --batch data/companies.txt \
  --workers 5 --rate 5 --timeout 10 --retries 1 \
  --db output/services.sqlite \
  --raw-output output/observations.jsonl \
  --unknowns output/unknowns.json \
  --format json --output output/report.json

# Use another resolver; DNSSEC checking is not disabled
python3 txt_enum.py --domain example.com --resolver cloudflare

# Deeper SPF exploration (bounded, cycles suppressed)
python3 txt_enum.py --domain example.com --spf-depth 2 --max-queries 20

# Reapply an edited catalog with zero DNS requests; export CSV
python3 txt_enum.py --replay output/observations.jsonl \
  --fingerprints catalogs/txt_fingerprints.json \
  --format csv --output output/matches.csv --unknowns output/unknowns.json

# Inspect your own saved observations offline
python3 txt_enum.py --replay output/observations.jsonl --format text
python3 txt_enum.py --list-services
python3 -m unittest discover -s tests -v

# Import live DNS JSON collected by an external approved transport, without
# calling it a cached web snapshot (schema described below)
python3 txt_enum.py --import-dns data/live-dns-sources.jsonl \
  --apex-only --format json --output output/replayed-live-dns.json
```

Input is a bare domain, not a URL or a company short name. Internationalized
domains are converted to IDNA. A supplied subdomain is queried as-is; this tool
does not guess the registrable domain or enumerate every DNS owner in a zone.

## What gets queried

By default, each input gets an apex TXT query, an `_dmarc` TXT query, and one
level of positive SPF `include` / `redirect` TXT expansion. The default budget
is 12 queries per domain. All requests are TXT over HTTPS to Google Public DNS
or Cloudflare. There are no SaaS login probes, MX lookups, zone transfers,
DKIM-selector guesses, or HTTP checks against the company. The recursive
resolver may return a CNAME chain as part of answering a TXT query.

`--apex-only` disables DMARC and SPF expansion. `--spf-depth 0` disables only SPF
expansion. `--rate` is a global requests-per-second limit across workers,
including retries. Each request has a timeout. Expansion budgets count query
names, not retry attempts. SPF macros are recorded but never expanded: their
meaning depends on a particular message and sender IP. This is not an SPF
policy validator and does not evaluate sender authorization, `all` reachability,
IP mechanisms, or DMARC external reporting authorization.

## Reading results

Each match has a rule ID, service, category, signal, confidence, exact TXT value,
matched substring/reference, DNS owner, queried name, timestamp, SPF path, and
attribution sources. JSON/JSONL query objects also preserve raw presentation,
TTL, DNS response code, resolver, URL, and the resolver's DNSSEC flag.

| Signal | What was observed | What it does not establish |
| --- | --- | --- |
| `domain_verification` | A recognizable vendor verification marker | Successful verification, paid account, specific product, or current usage |
| `spf_reference` | A positive include or redirect referencing a provider | Valid SPF policy, actual email traffic, or direct use when inherited through an upstream provider |
| `dmarc_reporting` | A known provider mailbox in `rua` / `ruf` | That the provider sends the company's email or actually receives reports |

Confidence describes **vendor attribution**. `high` rules have supporting vendor
documentation. `medium` rules were reviewed from explicit branded markers or
provider domain references; their notes explain the inference. Observation
sources are withheld from the public catalog, which sets
`observation_sources_withheld: true`; inferred rules may therefore have an empty
`sources` list. These attributions cannot be independently reproduced from the
bundled files alone. Neither level means confirmed active use. Google site
verification is labeled as generic Google domain verification because Search Console also uses it; it
is not automatically labeled Google Workspace. Microsoft domain verification
and Microsoft 365 email references are separate signals.

Matches include `association: direct` for records at the input name or its DMARC
owner, and `association: inherited` for records reached through SPF expansion.
Services found only upstream are labeled "inherited via SPF" in text output;
CSV includes an `association` column. Service summaries retain separate
`direct_evidence_count` and `inherited_evidence_count` values. A service with both
is labeled direct. Summary counts distinguish `direct_company_service_pairs`
from `inherited_only_company_service_pairs`; `company_service_pairs` includes both.
See [the accuracy guide](ACCURACY.md) for interpretation across both tools.

Rules anchor verification strings and compare SPF/DMARC domains at DNS label
boundaries. `sendgrid.net.evil.example` does not match SendGrid. SPF discovery
does not copy verification markers found on an upstream provider into the
customer's service list. Separate TXT resource records remain separate; quoted
character strings within a single record are joined, including DNS escapes.

`ok`, `no_data`, `nxdomain`, `partial`, and `error` are distinct domain statuses.
Per-query statuses additionally distinguish SERVFAIL, REFUSED, truncation, and
transport failures. Bounded SPF expansion can produce `partial`. No matches
is not proof that a service is absent. Exit status is 0 for a usable run, 1 if
all domains failed (or any are incomplete with `--strict`), 2 for invalid input,
and 130 for an interrupt. Progress goes to stderr so JSON stdout stays usable.
Outputs are finalized after collection; an interrupted scan is not checkpointed.

CSV has one row per evidence match and a status row for domains with no matches.
Conflicting input/output paths are rejected before collecting DNS records.
Formula-like text is escaped for spreadsheet import. JSON/JSONL retains original
values. SQLite is append-only per run; no previous run is overwritten.

## SQLite queries

The tables are `runs`, `domains`, `queries`, `records`, and `matches`.
`domains.result_json` keeps the complete domain result; `runs.metadata_json`
records the catalog hash, version, execution options, and collection method.
Use the run ID to avoid mixing historical snapshots:

```sql
-- Vendor prevalence in the latest run
SELECT m.service, COUNT(DISTINCT d.domain) AS domains
FROM matches AS m JOIN domains AS d ON d.id = m.domain_id
WHERE d.run_id = (SELECT MAX(id) FROM runs)
GROUP BY m.service ORDER BY domains DESC, m.service;

-- Exact evidence and query origin for a domain
SELECT d.domain, m.service, m.confidence, m.signal, q.query_name,
       q.fetched_at, q.resolver, r.value, m.rule_id
FROM matches AS m
JOIN domains AS d ON d.id = m.domain_id
JOIN records AS r ON r.id = m.record_id
JOIN queries AS q ON q.id = r.query_id
WHERE d.domain = 'example.com' AND d.run_id = (SELECT MAX(id) FROM runs);

-- Incomplete observations, not negative matches
SELECT domain, status FROM domains
WHERE run_id = (SELECT MAX(id) FROM runs) AND status IN ('error', 'partial');
```

The separately generated `data/technology_map.sqlite` database is the reusable
rules catalog. Create it with `python3 scripts/build_catalog_db.py`; it is not
included in the checkout. Keep it separate from `output/services.sqlite`.
Its `fingerprints` table stores `rule_id`, `service`, `kind`, `pattern`,
`domains_json`, confidence, basis, source URLs, and the complete JSON rule.
`catalog_metadata` stores its version and catalog file hash. For example:

```sql
SELECT pattern, service, confidence FROM fingerprints WHERE kind = 'txt_regex';
```

`--import-dns` accepts one JSON object per line with `domain`, `retrieved_at`,
`source_url`, and `payload` (the complete Google/Cloudflare DNS JSON response).
Optional `provider` and `transport` identify the collector. Failed attempts have
`payload: null` and `error`. This explicit import mode records
`collection_method: live_doh_import`; it does not make network requests itself.
It rejects extracted website tables, which belong in `--import-web` instead.
Third-party table imports preserve `source_observed_at` when supplied, separately
from the retrieval timestamp. Neither import mode independently verifies its input.

## Layout

- `txt_enum.py`: CLI, bounded collection, offline replay, reporting.
- `modules/txt_dns.py`: DoH transport, TXT decoding, DNS status handling.
- `modules/txt_matcher.py`: deterministic matching and unknown-pattern grouping.
- `modules/txt_storage.py`: SQLite persistence and summary statistics.
- `catalogs/txt_fingerprints.json`: distributable generic detection rules; no
  scanned-domain provenance or raw observations.
- `scripts/build_catalog_db.py`: generate a local SQLite rules database offline.
- `data/`: your local domain lists, custom catalogs, and generated rules database;
  ignored by Git and absent from a fresh checkout.
- `output/`: your generated scan database, raw observations, and reports; ignored
  by Git and created when writing results.
- `tests/`: synthetic parsing, matching, recursion, persistence, import, CLI, and
  database-generation tests that run without collected data.

## References

- [Google DNS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Cloudflare DNS JSON API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [SPF specification, RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)

The catalog retains vendor-documentation links where available. Observation
evidence and lookup URLs remain local and are not distributed.
