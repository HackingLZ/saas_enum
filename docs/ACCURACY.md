# Interpreting provider and TXT evidence

Both tools collect unauthenticated evidence. Neither proves a paid account,
current usage, ownership by a particular legal entity, or successful sign-in.

## Provider mode: compare a random tenant

A URL such as `example.provider.example` can resolve and redirect to a login
page even when the requested tenant does not exist. Provider mode checks a
random 16-character tenant using the same hostname template before describing
page evidence as corroborated.

1. Resolve the candidate hostname. DNS failures stay distinct from absent records.
2. Resolve the random control hostname. Any returned records are possible wildcard
   behavior, even when the control and candidate receive different rotating IPs.
3. Fetch the candidate page over HTTPS with certificate verification. Generic
   SSO/login URLs, company-name substrings, echoed URLs, and form/asset URLs do not
   qualify as strong company evidence. Missing-tenant and placeholder pages do
   not provide positive evidence either.
4. When the control resolves and the candidate returns a page, fetch the control
   page too. Compare final login destinations, visible page text with the supplied
   tenant name masked, and whether the random name also appears as supposed
   company evidence. Query parameters such as OAuth state and return URLs do not
   distinguish otherwise identical login endpoints.
5. Corroborate only when a standalone company reference remains and the control
   is observably different or has no DNS records. Incomplete controls never
   upgrade a candidate to corroborated.

This reduces common false positives; it does not turn a page match into proof
of active use. Dynamic pages, bot challenges, authentication gateways, arbitrary
branding, alternate tenant names, and shared names can still limit attribution.
A conservative result may miss a real tenant. One randomized control is a sample
of a provider's behavior, not an exhaustive test of its routing.

## Reading provider results

The existing JSON `status` values are retained for compatibility. Human-readable
output calls positive results **corroborated associations**. Every normal provider
result includes `association` (`candidate` or `corroborated`) and
`active_use_verified: false`.

| Status | Meaning |
| --- | --- |
| `confirmed_valid`, `confirmed_via_web` | Company-specific page evidence with a completed, distinguishable control; active use remains unverified. |
| `wildcard_match` | The random tenant resolves and the checks do not establish a distinct company page, or the control reproduces the candidate's page/login behavior. |
| `valid_dns`, `dns_only_match` | DNS evidence exists, but page evidence is absent, unavailable, or insufficient. |
| `url_only_match` | The name appears in URL/link evidence only. |
| `no_record` | No records were found for this hostname; other tenant names or providers may still be used. |
| `error`, `timeout` | The check is incomplete. Do not interpret it as absence. |

JSON includes `control_check` with the randomized hostname, DNS results, page
observations when available, and a verdict. Verdicts such as `shared_login`,
`shared_page`, and `reflected_name` explain why apparent positives were rejected.
`inconclusive` means the comparison could not be completed. `no_control_dns`
means the random hostname returned no records. `different` means the control
page differed without reproducing the company evidence, or returned HTTP 404/410.
Other control HTTP failures, including 403, remain inconclusive.

Use a JSON report to inspect both sides:

```bash
mkdir -p output
python saas_enum.py -i example -p Salesforce --format json --output output/provider-report.json
```

Custom `--yaml` catalogs apply to both single and batch scans. Provider selection
is case-insensitive; unknown or empty selections fail before scanning instead of
falling back to all providers. Missing YAML files produce errors and are not
silently replaced with a sample catalog.

## TXT mode: direct and inherited references

A company TXT record can reference an email provider whose own SPF records
reference additional services. Those downstream services may support the
provider's infrastructure rather than the company's own account.

TXT matches and service summaries therefore include `association`:

- `direct`: the rule matched a record at the requested name or its DMARC owner.
- `inherited`: the rule matched only while following an upstream SPF include or
  redirect. The match's `via` path identifies how it was reached.

Service summaries also include `direct_evidence_count` and
`inherited_evidence_count`. A service with both kinds is labeled direct while
retaining both counts. Text output labels inherited results, CSV includes an
`association` column, and JSON summaries separate direct associations from
inherited-only associations. The existing `company_service_pairs` total still
includes both.

Attribution confidence describes whether the signature identifies a provider.
It does not establish the relationship between that provider and the company.
Even a direct verification marker can be stale, and a direct DMARC destination
identifies reporting infrastructure rather than an email sender.

## Running accuracy tests

The tests use synthetic domains, DNS answers, and HTTP pages; no real tenant
scans are performed by the suite.

```bash
# Both modes
pip install -r requirements.txt
python -m unittest discover -s tests -v

# TXT tests also work without third-party packages; provider tests are skipped.
python3 -S -m unittest discover -s tests -v
```
