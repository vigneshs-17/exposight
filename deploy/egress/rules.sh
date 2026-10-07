#!/bin/sh
# Worker egress firewall rules (Phase D-2, STATUS.md "Phase D plan").
#
# Runs inside the egress container. The worker shares this network namespace, so
# these OUTPUT rules apply to every connection the worker opens. The worker has no
# NET_ADMIN and cannot change them.
#
# Allowed: loopback (Docker's embedded DNS at 127.0.0.11, forwarding to 1.1.1.1 /
# 9.9.9.9), replies on existing connections, Postgres on the db service's fixed IP
# only, and the public internet. Rejected: private, loopback, link-local (cloud
# metadata 169.254.169.254), CGNAT, documentation, benchmark, multicast and reserved
# IPv4 ranges. IPv6: everything except loopback is dropped (D12).
#
# Rejects use icmp-admin-prohibited, so a blocked connect fails at once with
# "No route to host" (EHOSTUNREACH) instead of timing out, and scripts/egress_check.py
# can tell the firewall apart from a closed port (ECONNREFUSED).
set -eu

DB_IP="${EGRESS_DB_IP:?EGRESS_DB_IP must be set to the db service static IP}"

iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -d "$DB_IP" --dport 5432 -j ACCEPT
for net in \
    0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 \
    192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 \
    203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
    iptables -A OUTPUT -d "$net" -j REJECT --reject-with icmp-admin-prohibited
done

ip6tables -F OUTPUT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -P OUTPUT DROP

# Read by the healthcheck; written only after every rule above was applied.
touch /run/egress-ready
echo "egress rules applied (db ${DB_IP}:5432 allowed)"
