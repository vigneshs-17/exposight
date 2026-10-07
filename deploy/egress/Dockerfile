# Worker egress firewall (Phase D-2). The worker joins this container's network
# namespace (network_mode: "service:egress"); only this container holds NET_ADMIN.
FROM alpine:3.22.6

RUN apk add --no-cache iptables ip6tables

COPY rules.sh /usr/local/bin/egress-rules.sh
RUN chmod 0755 /usr/local/bin/egress-rules.sh

# Apply the rules, then idle. If the script fails the container exits, its
# healthcheck never passes and the worker (depends_on: service_healthy) never starts.
ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/egress-rules.sh && exec sleep infinity"]
