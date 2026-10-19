# Uptime monitoring (owner)

`GET https://exposight.dev/health` answers `200` when the api runs and can reach the database, and `503` when the database connection fails. An external check on it sees what a user sees: DNS, Caddy, TLS, api and database.

## UptimeRobot (free plan)

1. Sign up at uptimerobot.com with your own email address.
2. **Add New Monitor**:
   - Monitor type: **HTTP(s)**
   - Friendly name: `exposight.dev health`
   - URL: `https://exposight.dev/health`
   - Monitoring interval: 5 minutes (free plan)
3. **Alert contacts**: select your email address (verified at sign-up). Notify when down.
4. Save. The first check runs within a few minutes and must show **Up**.

UptimeRobot also warns when the TLS certificate is about to expire (Monitor → SSL settings, if your plan offers it). Caddy renews automatically, so a warning means renewal is failing.

## Alternative: Healthchecks.io

Healthchecks.io is built for heartbeats (a job pings it; no ping = alert). It fits the daily backup: add `&& curl -fsS -m 10 --retry 3 https://hc-ping.com/<your-uuid>` to the end of the backup cron line in `docs/BACKUP_SETUP.md`, set the check period to 1 day with a 1-hour grace time, and set the email integration to your address.

## What this does not cover

- The worker. `/health` checks the api and database only; a stopped worker (no scans, no alert emails) still shows **Up**. Check `docker compose -f compose.prod.yml ps worker` after each deploy and if scans stop finishing.
- Disk space on the VM. Check `df -h /` occasionally; logs are capped at about 30 MB per container and backups at 7 days, but Docker images grow with every rebuild (`docker image prune` removes unused ones).

## Test the alert

Stop the api for a few minutes in a quiet period (`docker compose -f compose.prod.yml stop api`), wait for the down email, then `docker compose -f compose.prod.yml start api` and wait for the up email.
