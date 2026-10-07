"""Worker egress firewall check (Phase D-2).

Runs inside the worker container, so it sees exactly what the worker's network
namespace allows. Standard library only; nothing is installed in the image:

    docker compose -f compose.prod.yml exec -T worker python - < scripts/egress_check.py

Each target is one TCP connect. Expected outcomes:
- CONNECTED: the connect succeeded.
- BLOCKED: refused by the egress firewall. The rules reject with
  icmp-admin-prohibited, so the connect fails at once with "No route to host"
  (EHOSTUNREACH). A closed port (ECONNREFUSED) or a timeout is NOT accepted as
  blocked: it would also happen with no firewall at all.

Prints one line per target and exits 1 if any target differs from its expectation.
"""

from __future__ import annotations

import errno
import os
import socket
import struct
import sys

TIMEOUT_SECONDS = 5.0
BLOCKED_ERRNOS = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EPERM}


def default_gateway() -> str | None:
    """Return the IPv4 default gateway of this network namespace (the bridge address)."""
    try:
        with open("/proc/net/route", encoding="ascii") as routes:
            for line in routes.readlines()[1:]:
                fields = line.split()
                if fields[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except OSError:
        pass
    return None


def probe(host: str, port: int) -> tuple[str, str]:
    """Connect once; return (outcome, detail)."""
    try:
        family, _, _, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
    except socket.gaierror as exc:
        return "DNS_FAILED", str(exc)
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        sock.connect(address)
        return "CONNECTED", address[0]
    except TimeoutError:
        return "TIMEOUT", address[0]
    except OSError as exc:
        if exc.errno in BLOCKED_ERRNOS:
            outcome = "BLOCKED"
        elif exc.errno == errno.ECONNREFUSED:
            outcome = "REFUSED"
        else:
            outcome = "ERROR"
        return outcome, f"{address[0]}: {exc.strerror}"
    finally:
        sock.close()


def targets() -> list[tuple[str, str, int, str]]:
    """(label, host, port, expected outcome)."""
    gateway = default_gateway() or "10.89.0.1"
    checks = [
        ("Postgres on the db service", "db", 5432, "CONNECTED"),
        ("api service (private address)", "api", 8000, "BLOCKED"),
        ("another private IP on 5432 (api)", "api", 5432, "BLOCKED"),
        ("bridge gateway / host", gateway, 22, "BLOCKED"),
        ("cloud metadata endpoint", "169.254.169.254", 80, "BLOCKED"),
        ("private network 10.0.0.1", "10.0.0.1", 22, "BLOCKED"),
        ("public IPv6 (IPv6 is off)", "2606:4700:4700::1111", 443, "BLOCKED"),
        ("crt.sh", "crt.sh", 443, "CONNECTED"),
        ("Cert Spotter", "api.certspotter.com", 443, "CONNECTED"),
        ("public IPv4 1.1.1.1", "1.1.1.1", 443, "CONNECTED"),
    ]
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    if smtp_host:
        smtp_port = int(os.environ.get("SMTP_PORT", "587") or 587)
        checks.append(("SMTP relay", smtp_host, smtp_port, "CONNECTED"))
    return checks


def main() -> int:
    failures = 0
    for label, host, port, expected in targets():
        outcome, detail = probe(host, port)
        ok = outcome == expected
        failures += not ok
        verdict = "OK  " if ok else "FAIL"
        target = f"{host}:{port}"
        print(f"{verdict} {label:34} {target:28} {outcome} (expected {expected}) {detail}")
    print("egress check:", "PASSED" if failures == 0 else f"FAILED ({failures} mismatches)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
