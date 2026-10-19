# DNS records for exposight.dev (owner adds at Dynadot)

Add these in Dynadot: **My Domains → exposight.dev → DNS Settings**. Keep the existing `A` record for the apex (it points to the VM, `172.198.136.164`).

## Apex hardening

| Host | Type | Value | Why |
|---|---|---|---|
| `@` | CAA | `0 issue "letsencrypt.org"` | Only Let's Encrypt (used by Caddy) may issue certificates for the domain. |
| `@` | CAA | `0 issuewild ";"` | No certificate authority may issue wildcard certificates. |
| `@` | TXT | `v=spf1 -all` | The apex sends no email; receivers reject mail that claims to come from it. |
| `_dmarc` | TXT | `v=DMARC1; p=reject; adkim=s; aspf=s` | Receivers reject unauthenticated mail from the apex. A subdomain with its own `_dmarc` record (below) uses its own policy instead. |

Do not add `sp=` to the apex DMARC record: `notify` has its own record, and other subdomains then inherit `p=reject`, which is correct because they send no mail.

## notify subdomain (alert email via Brevo, `docs/EMAIL_SETUP.md`)

Brevo shows the exact values when you add `notify.exposight.dev` as a domain. Copy them from Brevo; the shapes are:

| Host | Type | Value | Why |
|---|---|---|---|
| `notify` | TXT | `brevo-code:<value from Brevo>` | Proves to Brevo that you control the subdomain. |
| `brevo1._domainkey.notify` | CNAME | `b1.<value from Brevo>.dkim.brevo.com` | DKIM key 1: Brevo signs each email; receivers check the signature. |
| `brevo2._domainkey.notify` | CNAME | `b2.<value from Brevo>.dkim.brevo.com` | DKIM key 2 (Brevo rotates between the two). |
| `notify` | TXT | `v=spf1 include:spf.brevo.com -all` | Allows Brevo's servers to send for the subdomain, nothing else. |
| `_dmarc.notify` | TXT | `v=DMARC1; p=none; adkim=r; aspf=r` | Subdomain policy. Start with `p=none`; change to `p=reject` after test emails show DKIM and DMARC pass. |

If Brevo shows a single DKIM TXT record instead of two CNAMEs, add the TXT record it shows. The `brevo-code` TXT and the SPF TXT are two separate TXT records on `notify`; do not merge them.

Dynadot host names are relative to `exposight.dev`: enter `brevo1._domainkey.notify`, not the full name.

## Check

From any machine (PowerShell or bash):

```bash
nslookup -type=CAA exposight.dev 1.1.1.1
nslookup -type=TXT exposight.dev 1.1.1.1
nslookup -type=TXT _dmarc.exposight.dev 1.1.1.1
nslookup -type=TXT notify.exposight.dev 1.1.1.1
nslookup -type=TXT _dmarc.notify.exposight.dev 1.1.1.1
```

After adding CAA, Caddy renewals keep working because they use Let's Encrypt.
