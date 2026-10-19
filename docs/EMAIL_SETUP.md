# Email alerts setup (owner)

Exposight sends alert emails from the **worker** over SMTP. Email is off while `SMTP_HOST` is empty. This guide sets up a free Brevo account that sends from `notify.exposight.dev`.

## 1. What the app reads

The worker reads these variables (`src/asm/worker/worker.py`; passed through by `compose.prod.yml`):

| Variable | Value for Brevo | Notes |
|---|---|---|
| `SMTP_HOST` | `smtp-relay.brevo.com` | Empty = email off. |
| `SMTP_PORT` | `587` | Azure blocks outbound port 25. Do not use 25. |
| `SMTP_STARTTLS` | `true` | Upgrades to TLS and verifies the server certificate. |
| `SMTP_SSL` | `false` | Never set both `SMTP_SSL` and `SMTP_STARTTLS` to `true`. |
| `SMTP_FROM` | `alerts@notify.exposight.dev` | Must be on the domain authenticated in Brevo. |
| `SMTP_USERNAME` | Brevo SMTP login | Brevo: SMTP & API, SMTP tab ("Login"). |
| `SMTP_PASSWORD` | Brevo SMTP key | Brevo: SMTP & API, "Generate a new SMTP key". |
| `SMTP_TIMEOUT` | `10` | Seconds. |

If a username or password is set but neither TLS mode is on, the worker refuses to send and records a delivery error. Passwords are never logged.

## 2. Create the Brevo account

1. Sign up at brevo.com (free plan: 300 emails per day). Exposight limits alerts to 20 per domain per 24 hours.
2. Go to **Senders, Domains & Dedicated IPs → Domains → Add a domain** and enter `notify.exposight.dev` (the subdomain, not the apex).
3. Brevo shows the DNS records to add. Add them at Dynadot (see `docs/DNS_RECORDS.md`, section "notify subdomain"). Copy the values from Brevo exactly; they are unique to the account.
4. Click **Authenticate this email domain**. Verification can take up to 48 hours.
5. Go to **Senders** and add `alerts@notify.exposight.dev` as a sender.
6. Go to **SMTP & API → SMTP** and generate an SMTP key. Copy it only into the VM `.env` (step 3). Never paste it into chat, an issue or the repository.

Why a subdomain: the apex `exposight.dev` publishes `v=spf1 -all` and DMARC `p=reject` (nothing may send as the apex). `notify.exposight.dev` gets its own SPF, DKIM and DMARC records, so the apex policy does not block it, and a problem with the sending reputation stays on the subdomain.

## 3. Put the credentials on the VM (owner only)

```bash
ssh -i ~/.ssh/exposight_ed25519 exposight@172.198.136.164
cd /opt/exposight
nano .env          # set the eight SMTP_* values from the table above
chmod 600 .env
docker compose -f compose.prod.yml up -d worker   # recreate the worker so it reads the new values
```

Check the names without printing values:

```bash
awk -F= '/^SMTP_/ {print $1, (length($2) > 0 ? "set" : "EMPTY")}' .env
```

## 4. Before turning email on

Setting `SMTP_HOST` makes every pending notification eligible for delivery. Check first that the queued recipients are addresses you expect:

```bash
docker compose -f compose.prod.yml exec -T db sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT status, count(*) FROM alert_notifications GROUP BY status;"'
```

## 5. Send one test email

This sends one message to an address you choose, with the worker's own settings. Replace `you@example.com` with your own inbox:

```bash
docker compose -f compose.prod.yml exec -T worker python -c '
import os
from asm.alerts.delivery import send_smtp_email
send_smtp_email(
    os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), os.environ["SMTP_FROM"],
    "you@example.com", "Exposight SMTP test", "SMTP delivery from the worker works.",
    username=os.environ.get("SMTP_USERNAME") or None,
    password=os.environ.get("SMTP_PASSWORD") or None,
    use_starttls=os.environ.get("SMTP_STARTTLS") == "true",
    use_ssl=os.environ.get("SMTP_SSL") == "true",
)
print("sent")'
```

Then, in Gmail, open the message, choose **Show original**, and check `SPF: PASS`, `DKIM: PASS` and `DMARC: PASS`. When all three pass for a week, tighten `_dmarc.notify` to `p=reject` (`docs/DNS_RECORDS.md`).

A real alert: in the dashboard, set an alert recipient on a verified domain. The next scan that detects an alert-eligible change sends an email.
