# Provider hostname catalog

The default `saas_enum.py` mode reads `dns_integrations.yaml`. It contains
**158 provider labels / 157 distinct hostname templates**. The 20 additions
listed below have official documentation supporting their hostname format.
Machine-readable provenance and provider-specific limits are in
[provider_sources.json](../catalogs/provider_sources.json).

The original 138 entries predate this source review and were retained. This
expansion does not certify their current validity. One existing duplicate is
`SHORT_NAME.cloud.com`, shared by the two Citrix labels.

## Interpretation

Replace `SHORT_NAME` with a candidate company, organization, site, or stack
slug. Providers may use generated names, regional domains, custom domains,
division names, or multiple accounts. An absent match is not evidence that a
company does not use the service.

A documented hostname format only justifies trying a candidate. A DNS answer,
successful HTTP response, shared login redirect, or page that echoes the
supplied name does not establish a real tenant. Compare the candidate with a
random control and examine independent company-specific evidence. Even a
corroborated association does not verify active use or contractual ownership.

Careers sites, feedback portals, storefronts, and staging sites are labeled
separately below. Their presence does not prove an internal software deployment.

## Documented additions

| Provider | Candidate hostname | Surface | Official documentation |
| --- | --- | --- | --- |
| 1Password Business/Teams | `SHORT_NAME.1password.com` | tenant application | [Source](https://support.1password.com/sso-configure-okta/) |
| Aha! | `SHORT_NAME.aha.io` | tenant application | [Source](https://www.aha.io/api/v3/oauth2) |
| Canny | `SHORT_NAME.canny.io` | feedback portal | [Source](https://help.canny.io/en/articles/1625730-installing-canny) |
| Chargebee | `SHORT_NAME.chargebee.com` | tenant application | [Source](https://apidocs.chargebee.com/docs/api/v2/pcv-1/getting-started) |
| Gorgias | `SHORT_NAME.gorgias.com` | tenant application | [Source](https://docs.gorgias.com/en-US/create-a-gorgias-helpdesk-82010) |
| Grafana Cloud | `SHORT_NAME.grafana.net` | tenant application | [Source](https://grafana.com/docs/grafana-cloud/platform/security-and-account-management/account-management/cloud-stacks/create-update-stacks/) |
| LearnUpon | `SHORT_NAME.learnupon.com` | learning portal | [Source](https://support.learnupon.com/hc/en-us/articles/360004833358-White-label-your-portal-with-a-custom-URL) |
| Odoo (hosted database) | `SHORT_NAME.odoo.com` | tenant application | [Source](https://www.odoo.com/documentation/19.0/applications/websites/website/configuration/domain_names.html) |
| Personio | `SHORT_NAME.app.personio.com` | tenant application | [Source](https://support.personio.de/hc/en-us/articles/6692155343261-Troubleshoot-login-issues) |
| Pipedrive | `SHORT_NAME.pipedrive.com` | tenant application | [Source](https://support.pipedrive.com/en/article/changing-a-company-domain-in-pipedrive) |
| Tellent Recruitee (careers) | `SHORT_NAME.recruitee.com` | careers site | [Source](https://support.recruitee.com/en/articles/1066308-manage-your-careers-site-s-url-and-search-visibility) |
| Recurly | `SHORT_NAME.recurly.com` | tenant application | [Source](https://docs.recurly.com/recurly-subscriptions/reference/createsubscription) |
| Retool | `SHORT_NAME.retool.com` | tenant application | [Source](https://docs.retool.com/org-users/quickstart) |
| Sentry | `SHORT_NAME.sentry.io` | tenant application | [Source](https://docs.sentry.io/api/organizations/retrieve-an-organization/) |
| Shopify (storefront) | `SHORT_NAME.myshopify.com` | storefront | [Source](https://help.shopify.com/en/manual/intro-to-shopify/initial-setup/setup-business-settings) |
| Teamtailor (careers) | `SHORT_NAME.teamtailor.com` | careers site | [Source](https://support.teamtailor.com/en/articles/10942490-work-with-our-divisions-feature) |
| Teamwork.com | `SHORT_NAME.teamwork.com` | tenant application | [Source](https://support.teamwork.com/projects/settings-administrator-only/changing-the-address-url-of-your-teamwork-site) |
| Tines | `SHORT_NAME.tines.com` | tenant application | [Source](https://www.tines.com/stories/docs/quickstart/signing-in/) |
| UserVoice | `SHORT_NAME.uservoice.com` | feedback portal | [Source](https://help.uservoice.com/hc/en-us/articles/360034982994-Set-up-your-own-URL-domain-for-UserVoice) |
| Webflow (staging site) | `SHORT_NAME.webflow.io` | staging site | [Source](https://help.webflow.com/hc/en-us/articles/33961419650067-Webflow-staging-subdomain) |

## Contributing patterns

Add a provider only when official documentation supports a hostname with
one `SHORT_NAME` placeholder. Keep source URLs and ambiguity notes in the
provenance file. Patterns requiring an additional unknown region, account ID,
or path parameter need a different input model and should not be guessed.

Use generic definitions only. Keep scan inputs, DNS evidence, response
captures, and reports in the ignored `data/` or `output/` directories.
