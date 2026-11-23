# SaaS Enum

SaaS Enum is a command line tool for discovering the SaaS platforms a company may be using. The tool looks for DNS entries that match known provider patterns and optionally performs lightweight web checks for confirmation.

The default mode takes a company short name and uses `dns_integrations.yaml`;
it does not require a database. For full-domain TXT lookups, see
[TXT service discovery](#txt-service-discovery) below.

## Installation

Install dependencies for the default provider-subdomain mode:

```bash
pip install -r requirements.txt
```

## Usage

### Basic check

Provide the company short name (subdomain) to test against all providers:
```bash
python saas_enum.py -i example
```

### Batch mode
Process multiple companies from a file and save the results as CSV:
```bash
mkdir -p data output
# Create data/company_short_names.txt with one company short name per line.
python saas_enum.py -b data/company_short_names.txt -o output/results.csv -f csv
```

### List providers
Display all provider templates defined in `dns_integrations.yaml`:
```bash
python saas_enum.py --list-providers
```

## Command line options

- `-i`, `--input` SHORT_NAME\
  Short name of the company to check.
- `-b`, `--batch` FILE\
  File containing multiple short names to check (one per line).
- `-p`, `--providers` NAMES\
  Comma separated list of specific providers to check.
- `-j`, `--json`\
  Output results in JSON format when used with a single check.
- `-o`, `--output` FILE\
  Save output to the specified file.
- `-f`, `--format` {text,json,csv}\
  Output format for saved results. Defaults to `text`.
- `-w`, `--workers` NUM\
  Maximum number of concurrent worker threads (default: 10).
- `-l`, `--list-providers`\
  List all available providers and exit.
- `-c`, `--check-providers`\
  Validate provider patterns for wildcard DNS.
- `-y`, `--yaml` PATH\
  Provider YAML file (defaults to `dns_integrations.yaml` beside the script).
- `-t`, `--timeout` SECONDS\
  Timeout in seconds for each provider check (default: 20).
- `-v`, `--verbose`\
  Show detailed output for all checks.

The supporting modules are located in the `modules` directory.

## Features

- DNS-based SaaS provider enumeration
- Optional HTTP verification of provider pages
- Batch processing with CSV or JSON reporting

## Interpreting provider results

Provider mode compares candidate tenants against randomized control tenants.
Shared login redirects, pages that echo any tenant name, and incomplete controls
remain unconfirmed. Positive results are **corroborated associations**, with
active use still unverified. See [accuracy checks and result meanings](docs/ACCURACY.md).

Custom `--yaml` files apply to single and batch scans. Provider selections are
case-insensitive, and unknown selections fail before any checks run.

The provider catalog contains **158 labels / 157 distinct hostname templates**.
The [20 newly documented additions](docs/PROVIDERS.md) include Retool, Grafana
Cloud, Personio, Tines, and 1Password. Each addition has official source links
and notes about tenant naming and the type of site it identifies.

## TXT service discovery

Look up full domain names and match TXT records against generic detection rules.
TXT mode requires Python 3.10+ and uses only the standard library; no API key or
package installation is needed.

**Databases and collected data are not included. Each user must generate their
own databases locally.** The repository includes only the generic rules in
[`catalogs/txt_fingerprints.json`](catalogs/txt_fingerprints.json), with scanned
domains, raw DNS evidence, and observation lookup URLs removed.

### Generate the rules database

From a fresh checkout, run:

```bash
python3 scripts/build_catalog_db.py
```

This creates `data/technology_map.sqlite` offline from the bundled JSON catalog.
It contains **346 fingerprints / 314 service labels**, including domain
verification markers, SPF provider references, and a DMARC reporting signature.
It does not contain any scanned companies or their records. The command refuses
to overwrite an existing file; use `--output data/technology_map-new.sqlite` to
build another copy after updating the rules.

The CLI reads the JSON catalog directly, so the SQLite rules database is optional
unless you want to query or integrate the rules through SQL.

### Generate your own scan database

A scan database is separate from the rules database. Create `data/companies.txt`
with your own full domain names, one per line. For a first-run example:

```bash
mkdir -p data
# Replace these example domains with your own before collecting results.
# Create this file only if it does not already exist.
python3 -c 'from pathlib import Path; Path("data/companies.txt").open("x").write("example.com\nexample.org\n")'
python3 saas_enum.py --txt --batch data/companies.txt \
  --db output/services.sqlite --raw-output output/observations.jsonl \
  --unknowns output/unknowns.json --format json --output output/report.json
```

The scan performs live DNS-over-HTTPS queries and creates the output directory,
SQLite scan database, observations, and report. Repeated runs append scan history
to `output/services.sqlite`; the report files are replaced. For a single domain:

```bash
python3 saas_enum.py --txt --domain example.com --db output/services.sqlite
```

Results describe DNS evidence and vendor attribution, not confirmed active product
use. Results distinguish direct DNS references from services inherited through
upstream SPF records. Of the bundled rules, 34 link to vendor documentation and 312 are explicitly
labeled inferences whose observation sources are withheld. See
[TXT usage and database queries](docs/TXT.md) and
[how to curate the catalog](docs/CURATING.md).

## Local data and publishing

`data/`, `output/`, database files, collected JSONL/CSV files, environment files,
and common credential files are excluded by `.gitignore`. Keep your domain lists,
raw observations, reports, and custom catalogs in those local directories. Review
`git status --short` and `git diff --cached` before committing; ignore rules do not
remove files already tracked by Git or prevent a forced add.

The test suite uses synthetic fixtures and runs without a local database or
collected dataset. Install `requirements.txt` to test both modes; without those
packages, provider-mode tests are skipped and TXT tests still run:

```bash
python3 -m unittest discover -s tests -v
```

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
