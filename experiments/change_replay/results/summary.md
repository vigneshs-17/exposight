# E-1a: P0 false changes under seeded scan noise

Seeds 1-20; 9 labelled real events per seed; each noise class alone at its realistic probability, then all combined.
Regenerate: `python -m experiments.change_replay.run --seed 1 --seeds 20`.

| profile | p | asset-scans | false changes | per 1,000 | alert-eligible per 1,000 | missed events | mean delay | max delay |
|---|---|---|---|---|---|---|---|---|
| zero | - | 7080 | 0 | 0.00 | 0.00 | 0 | 0.00 | 0 |
| dns_timeout | 0.01 | 7080 | 203 | 28.67 | 4.52 | 3 | 0.00 | 0 |
| dns_nxdomain | 0.002 | 7080 | 92 | 12.99 | 0.85 | 0 | 0.00 | 0 |
| ct_partial | 0.02 | 7080 | 114 | 16.10 | 0.56 | 1 | 0.00 | 0 |
| ct_truncated | 0.02 | 7080 | 84 | 11.86 | 1.55 | 1 | 0.00 | 0 |
| port_flap_filtered | 0.01 | 7080 | 155 | 21.89 | 3.11 | 1 | 0.00 | 0 |
| port_flap_closed | 0.005 | 7080 | 146 | 20.62 | 2.26 | 0 | 0.00 | 0 |
| cdn_edge | 0.1 | 7080 | 295 | 41.67 | 0.00 | 2 | 0.00 | 0 |
| probe_https_fail | 0.005 | 7080 | 69 | 9.75 | 3.95 | 2 | 0.00 | 0 |
| inspect_timeout | 0.005 | 7080 | 17 | 2.40 | 0.00 | 1 | 0.00 | 0 |
| combined | - | 7080 | 1116 | 157.63 | 11.86 | 7 | 0.01 | 1 |

## False changes by change_type (per 1,000 asset-scans)

| profile | change_type | count | per 1,000 | alert-eligible |
|---|---|---|---|---|
| dns_timeout | PORT_NEWLY_OPEN | 137 | 19.35 | 32 |
| dns_timeout | HOST_RISK_BAND_INCREASED | 28 | 3.95 | 0 |
| dns_timeout | HOST_RISK_BAND_DECREASED | 26 | 3.67 | 0 |
| dns_timeout | DOMAIN_RISK_BAND_DECREASED | 6 | 0.85 | 0 |
| dns_timeout | DOMAIN_RISK_BAND_INCREASED | 6 | 0.85 | 0 |
| dns_nxdomain | PORT_NEWLY_OPEN | 37 | 5.23 | 6 |
| dns_nxdomain | NEWLY_RESOLVING | 18 | 2.54 | 0 |
| dns_nxdomain | STOPPED_RESOLVING | 17 | 2.40 | 0 |
| dns_nxdomain | HOST_RISK_BAND_DECREASED | 8 | 1.13 | 0 |
| dns_nxdomain | HOST_RISK_BAND_INCREASED | 8 | 1.13 | 0 |
| dns_nxdomain | DOMAIN_RISK_BAND_DECREASED | 2 | 0.28 | 0 |
| dns_nxdomain | DOMAIN_RISK_BAND_INCREASED | 2 | 0.28 | 0 |
| ct_partial | PORT_NEWLY_OPEN | 48 | 6.78 | 4 |
| ct_partial | REMOVED_SUBDOMAIN | 30 | 4.24 | 0 |
| ct_partial | NEW_SUBDOMAIN | 28 | 3.95 | 0 |
| ct_partial | DOMAIN_RISK_BAND_DECREASED | 4 | 0.56 | 0 |
| ct_partial | DOMAIN_RISK_BAND_INCREASED | 4 | 0.56 | 0 |
| ct_truncated | PORT_NEWLY_OPEN | 56 | 7.91 | 11 |
| ct_truncated | NEW_SUBDOMAIN | 25 | 3.53 | 0 |
| ct_truncated | DOMAIN_RISK_BAND_DECREASED | 2 | 0.28 | 0 |
| ct_truncated | DOMAIN_RISK_BAND_INCREASED | 1 | 0.14 | 0 |
| port_flap_filtered | PORT_NEWLY_OPEN | 126 | 17.80 | 22 |
| port_flap_filtered | HOST_RISK_BAND_DECREASED | 10 | 1.41 | 0 |
| port_flap_filtered | HOST_RISK_BAND_INCREASED | 9 | 1.27 | 0 |
| port_flap_filtered | DOMAIN_RISK_BAND_DECREASED | 5 | 0.71 | 0 |
| port_flap_filtered | DOMAIN_RISK_BAND_INCREASED | 5 | 0.71 | 0 |
| port_flap_closed | PORT_NO_LONGER_OPEN | 66 | 9.32 | 0 |
| port_flap_closed | PORT_NEWLY_OPEN | 64 | 9.04 | 16 |
| port_flap_closed | DOMAIN_RISK_BAND_DECREASED | 4 | 0.56 | 0 |
| port_flap_closed | DOMAIN_RISK_BAND_INCREASED | 4 | 0.56 | 0 |
| port_flap_closed | HOST_RISK_BAND_DECREASED | 4 | 0.56 | 0 |
| port_flap_closed | HOST_RISK_BAND_INCREASED | 4 | 0.56 | 0 |
| cdn_edge | CERTIFICATE_CHANGED | 295 | 41.67 | 0 |
| probe_https_fail | HTTPS_LOST | 28 | 3.95 | 28 |
| probe_https_fail | HOST_RISK_BAND_INCREASED | 21 | 2.97 | 0 |
| probe_https_fail | HOST_RISK_BAND_DECREASED | 20 | 2.82 | 0 |
| inspect_timeout | SECURITY_HEADER_REMOVED | 7 | 0.99 | 0 |
| inspect_timeout | HOST_RISK_BAND_DECREASED | 5 | 0.71 | 0 |
| inspect_timeout | HOST_RISK_BAND_INCREASED | 5 | 0.71 | 0 |
| combined | PORT_NEWLY_OPEN | 454 | 64.12 | 60 |
| combined | CERTIFICATE_CHANGED | 285 | 40.25 | 0 |
| combined | HOST_RISK_BAND_INCREASED | 67 | 9.46 | 0 |
| combined | HOST_RISK_BAND_DECREASED | 63 | 8.90 | 0 |
| combined | PORT_NO_LONGER_OPEN | 61 | 8.62 | 0 |
| combined | NEW_SUBDOMAIN | 52 | 7.34 | 0 |
| combined | REMOVED_SUBDOMAIN | 30 | 4.24 | 0 |
| combined | HTTPS_LOST | 24 | 3.39 | 24 |
| combined | DOMAIN_RISK_BAND_DECREASED | 20 | 2.82 | 0 |
| combined | NEWLY_RESOLVING | 18 | 2.54 | 0 |
| combined | DOMAIN_RISK_BAND_INCREASED | 17 | 2.40 | 0 |
| combined | STOPPED_RESOLVING | 17 | 2.40 | 0 |
| combined | SECURITY_HEADER_REMOVED | 8 | 1.13 | 0 |

## Stop rule (combined profile)

- false changes per 1,000 <= 1.0: FAIL
- alert-eligible false per 1,000 <= 0.1: FAIL
- missed real events <= 0: FAIL

**Verdict: NOT NEGLIGIBLE.**
