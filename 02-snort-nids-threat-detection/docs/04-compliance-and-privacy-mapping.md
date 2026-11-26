# 04 · Governance Mapping: NIST SP 800-94, MITRE ATT&CK, OWASP, ISO 27001, UU PDP

> Informational mapping for a lab project. Not legal advice; verify article numbers against the official text before citing in a real compliance document.

## 1. NIST SP 800-94 (Guide to IDPS) – how the project applies it
| Guide concept | Application in this project |
|---|---|
| Detection methodologies (signature / anomaly / stateful protocol) | Signature + threshold rules; limits documented (FN1, FN4) |
| IDPS deployment & sensor placement (passive vs inline) | Passive sensor in front of the protected segment – [02](02-threat-model-and-architecture.md) |
| Tuning (reducing false positives/negatives) | Priority tiers, `event_filter`, `suppress`, two-tier SQLi rules – [03](03-fp-fn-tuning.md) |
| Security of the IDPS itself | STRIDE for sensor/logs – [02 §3](02-threat-model-and-architecture.md) |
| Alert handling & response integration | Triage runbook – [07](07-alert-triage-runbook.md) |

## 2. MITRE ATT&CK coverage
| Tactic | Technique | SID(s) | Coverage | Gap |
|---|---|---|---|---|
| Reconnaissance | T1595.001 Scanning IP Blocks | 1000004, 1000001 | Partial | Slow scans |
| Reconnaissance | T1595.002 Vulnerability Scanning | 1000005 | Partial | UA spoofing |
| Discovery | T1046 Network Service Discovery | 1000001 | Partial | Slow scans, internal-source scans if sensor is north-south only |
| Credential Access | T1110 Brute Force | 1000002 | **Weak** (rate proxy only) | Auth outcome invisible |
| Initial Access | T1190 Exploit Public-Facing Application | 1000003, 1000006, 1000007 | Partial | Evasion (FN4/5), TLS |
| – | – | – | **Not covered:** C2, exfiltration, lateral movement, persistence | Out of scope; needs egress/DNS/host telemetry |

## 3. OWASP Top 10 (2021) / CWE
A03:2021 Injection · CWE-89 (SQL Injection). Detection (this project) is a *compensating* control; the *preventive* control is
parameterized queries (Project 01 remediation). Both layers are required (defence in depth).

## 4. ISO/IEC 27001:2022 Annex A (illustrative)
| Control | Relevance |
|---|---|
| 8.15 Logging | Alerts retained with timestamps, integrity manifest |
| 8.16 Monitoring activities | The NIDS itself |
| 8.20 Networks security | Segment monitoring, sensor placement |
| 5.24–5.26 Incident management planning / assessment / response | Triage runbook, severity tiers |
| 5.34 Privacy and protection of PII | Handling of pcaps/logs (§5 below) |

NIST CSF 2.0 reference: DE.CM-01 (network monitored for adverse events), DE.AE-02 (adverse events analysed).

## 5. Privacy governance – UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (UU PDP)
Network monitoring processes data that can identify people: **IP addresses, session cookies, credentials in URLs/forms, query strings**.
If the sensor protected a real production system, the operator would be a *Pengendali Data Pribadi* with duties including:

| Obligation (UU PDP, ref. to verify) | How this project handles it |
|---|---|
| Keamanan pemrosesan / security of processing (Pasal 35–39) | Sensor hardened per STRIDE table; logs outside web-reachable paths; access restricted |
| Data minimisation & purpose limitation (Pasal 16) | Alert-only logging by default; pcap only when `CAPTURE=1` and kept local; payload not committed |
| Retention | Define max retention for pcaps (e.g. 7–30 days) and alerts (e.g. 12 months for audit) |
| Breach notification ≤ 3×24 h (Pasal 46) | Runbook step: confirmed exfiltration/unauthorised access → escalate to DPO/legal immediately |
| Transparency | Network-monitoring notice in acceptable-use policy (production) |

**In this lab** all traffic is synthetic between assets I own, so no third-party personal data is processed; the controls above are
implemented anyway to demonstrate the practice. `06_sanitize_and_package.sh` blocks session IDs/passwords/keys from reaching GitHub.

## 6. Rules of engagement (authorization)
Attack simulations run only against my own lab assets. Scripts enforce an RFC1918/loopback guard and an explicit `LAB` confirmation.
Never run scripts 03/04 against systems without written permission.
