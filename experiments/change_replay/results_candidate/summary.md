# E-1a: Port-Inspection-Discovery-Probe Candidate false changes under seeded scan noise

Seeds 1-20; 9 labelled real events per seed; each noise class alone at its realistic probability, then all combined.
Regenerate: `python -m experiments.change_replay.run --seed 1 --seeds 20 --candidate`.

| profile | p | asset-scans | false changes | per 1,000 | alert-eligible per 1,000 | missed events | mean delay | max delay |
|---|---|---|---|---|---|---|---|---|
| zero | - | 7080 | 0 | 0.00 | 0.00 | 0 | 0.11 | 1 |
| dns_timeout | 0.01 | 7080 | 11 | 1.55 | 0.00 | 0 | 0.12 | 1 |
| dns_nxdomain | 0.002 | 7080 | 37 | 5.23 | 0.00 | 0 | 0.11 | 1 |
| ct_partial | 0.02 | 7080 | 4 | 0.56 | 0.00 | 0 | 0.12 | 1 |
| ct_truncated | 0.02 | 7080 | 1 | 0.14 | 0.00 | 0 | 0.12 | 1 |
| port_flap_filtered | 0.01 | 7080 | 2 | 0.28 | 0.00 | 0 | 0.11 | 1 |
| port_flap_closed | 0.005 | 7080 | 146 | 20.62 | 2.26 | 0 | 0.11 | 1 |
| cdn_edge | 0.1 | 7080 | 132 | 18.64 | 0.00 | 0 | 0.12 | 1 |
| probe_https_fail | 0.005 | 7080 | 0 | 0.00 | 0.00 | 0 | 0.11 | 1 |
| inspect_timeout | 0.005 | 7080 | 0 | 0.00 | 0.00 | 0 | 0.12 | 1 |
| combined | - | 7080 | 319 | 45.06 | 0.85 | 0 | 0.14 | 1 |

## False changes by change_type (per 1,000 asset-scans)

| profile | change_type | count | per 1,000 | alert-eligible |
|---|---|---|---|---|
| dns_timeout | PORT_NEWLY_OPEN | 10 | 1.41 | 0 |
| dns_timeout | HOST_RISK_BAND_INCREASED | 1 | 0.14 | 0 |
| dns_nxdomain | NEWLY_RESOLVING | 18 | 2.54 | 0 |
| dns_nxdomain | STOPPED_RESOLVING | 17 | 2.40 | 0 |
| dns_nxdomain | PORT_NEWLY_OPEN | 2 | 0.28 | 0 |
| ct_partial | PORT_NEWLY_OPEN | 2 | 0.28 | 0 |
| ct_partial | HOST_RISK_BAND_DECREASED | 1 | 0.14 | 0 |
| ct_partial | NEW_SUBDOMAIN | 1 | 0.14 | 0 |
| ct_truncated | HOST_RISK_BAND_DECREASED | 1 | 0.14 | 0 |
| port_flap_filtered | PORT_NEWLY_OPEN | 2 | 0.28 | 0 |
| port_flap_closed | PORT_NO_LONGER_OPEN | 66 | 9.32 | 0 |
| port_flap_closed | PORT_NEWLY_OPEN | 64 | 9.04 | 16 |
| port_flap_closed | DOMAIN_RISK_BAND_DECREASED | 4 | 0.56 | 0 |
| port_flap_closed | DOMAIN_RISK_BAND_INCREASED | 4 | 0.56 | 0 |
| port_flap_closed | HOST_RISK_BAND_DECREASED | 4 | 0.56 | 0 |
| port_flap_closed | HOST_RISK_BAND_INCREASED | 4 | 0.56 | 0 |
| cdn_edge | CERTIFICATE_CHANGED | 132 | 18.64 | 0 |
| combined | CERTIFICATE_CHANGED | 134 | 18.93 | 0 |
| combined | PORT_NEWLY_OPEN | 77 | 10.88 | 6 |
| combined | PORT_NO_LONGER_OPEN | 64 | 9.04 | 0 |
| combined | NEWLY_RESOLVING | 18 | 2.54 | 0 |
| combined | STOPPED_RESOLVING | 17 | 2.40 | 0 |
| combined | HOST_RISK_BAND_DECREASED | 3 | 0.42 | 0 |
| combined | HOST_RISK_BAND_INCREASED | 3 | 0.42 | 0 |
| combined | DOMAIN_RISK_BAND_DECREASED | 1 | 0.14 | 0 |
| combined | DOMAIN_RISK_BAND_INCREASED | 1 | 0.14 | 0 |
| combined | NEW_SUBDOMAIN | 1 | 0.14 | 0 |

## Stop rule (combined profile)

- informational false changes per 1,000: 45.06 (report-only)
- alert-eligible false per 1,000 <= 0.1: FAIL
- missed real events <= 0: pass

**Verdict: NOT NEGLIGIBLE.**
