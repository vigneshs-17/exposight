# E-1a: Port-Inspection-Discovery-Probe Candidate false changes under seeded scan noise

Seeds 1-80; 9 labelled real events per seed; each noise class alone at its realistic probability, then all combined.
Regenerate: `python -m experiments.change_replay.run --seed 1 --seeds 80 --candidate`.

| profile | p | asset-scans | false changes | per 1,000 | alert-eligible per 1,000 | missed events | mean delay | max delay |
|---|---|---|---|---|---|---|---|---|
| zero | - | 28320 | 0 | 0.00 | 0.00 | 0 | 0.11 | 1 |
| dns_timeout | 0.01 | 28320 | 32 | 1.13 | 0.00 | 0 | 0.11 | 1 |
| dns_nxdomain | 0.002 | 28320 | 117 | 4.13 | 0.00 | 0 | 0.11 | 1 |
| ct_partial | 0.02 | 28320 | 8 | 0.28 | 0.00 | 0 | 0.11 | 1 |
| ct_truncated | 0.02 | 28320 | 2 | 0.07 | 0.00 | 0 | 0.12 | 3 |
| port_flap_filtered | 0.01 | 28320 | 13 | 0.46 | 0.00 | 0 | 0.11 | 1 |
| port_flap_closed | 0.005 | 28320 | 584 | 20.62 | 0.00 | 0 | 0.11 | 1 |
| cdn_edge | 0.1 | 28320 | 544 | 19.21 | 0.00 | 0 | 0.12 | 2 |
| probe_https_fail | 0.005 | 28320 | 1 | 0.04 | 0.00 | 0 | 0.12 | 1 |
| inspect_timeout | 0.005 | 28320 | 1 | 0.04 | 0.00 | 0 | 0.12 | 1 |
| combined | - | 28320 | 1277 | 45.09 | 0.00 | 0 | 0.14 | 3 |

## False changes by change_type (per 1,000 asset-scans)

| profile | change_type | count | per 1,000 | alert-eligible |
|---|---|---|---|---|
| dns_timeout | PORT_OBSERVED_OPEN | 30 | 1.06 | 0 |
| dns_timeout | HOST_RISK_BAND_DECREASED | 1 | 0.04 | 0 |
| dns_timeout | HOST_RISK_BAND_INCREASED | 1 | 0.04 | 0 |
| dns_nxdomain | NEWLY_RESOLVING | 56 | 1.98 | 0 |
| dns_nxdomain | STOPPED_RESOLVING | 54 | 1.91 | 0 |
| dns_nxdomain | PORT_OBSERVED_OPEN | 7 | 0.25 | 0 |
| ct_partial | NEW_SUBDOMAIN | 2 | 0.07 | 0 |
| ct_partial | PORT_NEWLY_OPEN | 2 | 0.07 | 0 |
| ct_partial | DOMAIN_RISK_BAND_DECREASED | 1 | 0.04 | 0 |
| ct_partial | DOMAIN_RISK_BAND_INCREASED | 1 | 0.04 | 0 |
| ct_partial | HOST_RISK_BAND_DECREASED | 1 | 0.04 | 0 |
| ct_partial | REMOVED_SUBDOMAIN | 1 | 0.04 | 0 |
| ct_truncated | HOST_RISK_BAND_DECREASED | 1 | 0.04 | 0 |
| ct_truncated | HOST_RISK_BAND_INCREASED | 1 | 0.04 | 0 |
| port_flap_filtered | PORT_OBSERVED_OPEN | 11 | 0.39 | 0 |
| port_flap_filtered | DOMAIN_RISK_BAND_INCREASED | 1 | 0.04 | 0 |
| port_flap_filtered | HOST_RISK_BAND_INCREASED | 1 | 0.04 | 0 |
| port_flap_closed | PORT_NO_LONGER_OPEN | 266 | 9.39 | 0 |
| port_flap_closed | PORT_REOPENED | 258 | 9.11 | 0 |
| port_flap_closed | HOST_RISK_BAND_DECREASED | 14 | 0.49 | 0 |
| port_flap_closed | HOST_RISK_BAND_INCREASED | 13 | 0.46 | 0 |
| port_flap_closed | DOMAIN_RISK_BAND_DECREASED | 11 | 0.39 | 0 |
| port_flap_closed | DOMAIN_RISK_BAND_INCREASED | 11 | 0.39 | 0 |
| port_flap_closed | PORT_NEWLY_OPEN | 11 | 0.39 | 0 |
| cdn_edge | CERTIFICATE_CHANGED | 544 | 19.21 | 0 |
| probe_https_fail | HOST_RISK_BAND_DECREASED | 1 | 0.04 | 0 |
| inspect_timeout | HOST_RISK_BAND_DECREASED | 1 | 0.04 | 0 |
| combined | CERTIFICATE_CHANGED | 536 | 18.93 | 0 |
| combined | PORT_NO_LONGER_OPEN | 260 | 9.18 | 0 |
| combined | PORT_REOPENED | 249 | 8.79 | 0 |
| combined | NEWLY_RESOLVING | 56 | 1.98 | 0 |
| combined | STOPPED_RESOLVING | 53 | 1.87 | 0 |
| combined | PORT_OBSERVED_OPEN | 52 | 1.84 | 0 |
| combined | HOST_RISK_BAND_INCREASED | 18 | 0.64 | 0 |
| combined | HOST_RISK_BAND_DECREASED | 17 | 0.60 | 0 |
| combined | PORT_NEWLY_OPEN | 14 | 0.49 | 0 |
| combined | DOMAIN_RISK_BAND_INCREASED | 10 | 0.35 | 0 |
| combined | DOMAIN_RISK_BAND_DECREASED | 9 | 0.32 | 0 |
| combined | NEW_SUBDOMAIN | 2 | 0.07 | 0 |
| combined | REMOVED_SUBDOMAIN | 1 | 0.04 | 0 |

## Stop rule (combined profile)

- informational false changes per 1,000: 45.09 (report-only)
- alert-eligible false per 1,000 <= 0.1: pass
- missed real events <= 0: pass

**Verdict: NEGLIGIBLE: keep P0.**
