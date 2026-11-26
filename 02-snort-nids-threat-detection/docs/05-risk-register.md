# 05 · Risk Register – NIDS Deployment

Scoring: Likelihood (L) × Impact (I), each 1–5. Rating: 1–6 Low · 8–12 Medium · 15–25 High.

| ID | Risk | L | I | Score | Treatment | Owner (role) | Residual |
|---|---|---|---|---|---|---|---|
| R1 | Attacks inside encrypted traffic (TLS) go undetected | 5 | 4 | 20 High | Mitigate: TLS-terminating reverse proxy/WAF; host + app logs to SIEM; SID 1000008 telemetry measures exposure | Security Architect | Medium |
| R2 | Low-and-slow scanning/brute force evades thresholds | 4 | 3 | 12 Med | Mitigate: SIEM long-window correlation, unique-port logic (`port_scan`), fail2ban on hosts | SOC Lead | Low-Med |
| R3 | Alert fatigue from false positives leads to ignored true alerts | 4 | 4 | 16 High | Mitigate: priority tiers, suppression lists, monthly rule review with FP metrics | SOC Lead | Medium |
| R4 | Rule/engine drift (stale signatures, unpatched Snort) | 3 | 4 | 12 Med | Mitigate: rules in Git with review, pcap regression tests before deploy, patch cadence | Detection Engineer | Low |
| R5 | pcaps/alerts expose personal data or credentials | 3 | 5 | 15 High | Mitigate: minimise capture, encrypt at rest, retention limit, redaction before sharing, access control | DPO / Security | Low |
| R6 | Sensor overload → silent packet loss | 3 | 4 | 12 Med | Mitigate: drop-counter alerting, capacity planning, offload tuning | Network Eng. | Low |
| R7 | Sensor compromise or tampering (runs as root, parses hostile input) | 2 | 5 | 10 Med | Mitigate: management NIC isolation, FIM, privilege drop, patching | Security Architect | Low |
| R8 | Detection-only: no containment automation → slow response | 3 | 3 | 9 Med | Accept for now; define SLA in runbook; evaluate IPS/SOAR after FP rate proven | CISO | Medium |
| R9 | Single-sensor visibility gap (east-west, remote users) | 4 | 3 | 12 Med | Mitigate: SPAN/tap coverage plan, host-based telemetry | Network Eng. | Medium |

**Risk acceptance statement (example for CISO sign-off):** R1 is *partially accepted* for the lab; for production it must be treated before go-live.
