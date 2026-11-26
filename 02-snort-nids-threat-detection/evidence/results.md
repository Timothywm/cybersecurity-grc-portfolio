# Test Results (auto-generated)

_Generated 2026-11-26 08:19 from `alert_fast.txt` (20 alerts) and `attack-timeline.csv` (15 scenarios)._

## Summary

| Metric | Value |
|---|---|
| True-positive scenarios detected | **6/6** |
| Benign scenarios that raised a false positive | **3/3** |
| Evasion scenarios that went undetected (false negatives) | **2/5** |
| Alerts not attributable to any scenario | 0 |

## Scenario results

| ID | Type | Description | Expected SIDs | Fired SIDs | Alerts | Verdict |
|---|---|---|---|---|---|---|
| TP1 | TP | ICMP echo burst (10 pings / 2s) | 1000004 | 1000004 | 1 | **DETECTED** |
| TP2 | TP | Nmap SYN scan ports 1-1024 (-T4) | 1000001 | 1000001 | 1 | **DETECTED** |
| TP3 | TP | 12 SSH connection attempts in ~4s | 1000002 | 1000002 | 1 | **DETECTED** |
| TP4 | TP | SQLi UNION SELECT with column list (DVWA) | 1000003, 1000006 | 1000003, 1000006 | 2 | **DETECTED** |
| TP5 | TP | SQLi UNION ALL SELECT NULL enumeration | 1000003, 1000006 | 1000003, 1000006 | 2 | **DETECTED** |
| TP6 | TP | sqlmap User-Agent | 1000005 | 1000005 | 1 | **DETECTED** |
| FP1 | FP | Benign admin: 8 legit SSH sessions in ~4s (automation/Ansible-like) | - | 1000002 | 1 | **FALSE POSITIVE** |
| FP2 | FP | Benign search 'credit union select plan' (keyword collision) | - | 1000003 | 1 | **FALSE POSITIVE** |
| FP3 | FP | Uptime monitor: ping every 0.2s x8 | - | 1000004 | 1 | **FALSE POSITIVE** |
| FN1 | FN | Low-and-slow scan: ports 1-100, 1 probe/sec (evades 15/5s) | 1000001 | - | 0 | **MISSED (evasion succeeded)** |
| FN2 | FN | Obfuscation: mixed case UnIoN SeLeCt | 1000006 | 1000003, 1000006 | 2 | **DETECTED (evasion failed)** |
| FN3 | FN | Obfuscation: comment whitespace UNION/**/SELECT | 1000006 | 1000003, 1000006 | 2 | **DETECTED (evasion failed)** |
| FN4 | FN | Obfuscation: keyword split UN/**/ION SEL/**/ECT | 1000006 | - | 0 | **MISSED (evasion succeeded)** |
| FN5 | FN | Obfuscation: double URL-encoding %2555NION %2553ELECT | 1000006 | 1000003, 1000006 | 2 | **DETECTED (evasion failed)** |
| BS1 | BLINDSPOT | Same SQLi over TLS (8443). Expect: only telemetry 1000008, NOT 1000006 | 1000008 | 1000003, 1000006, 1000008 | 3 | **ATTACK STILL DETECTED** |

## Alerts per rule

| SID | Rule | Alerts |
|---|---|---|
| 1000001 | [RECON] TCP SYN scan - high-rate SYNs across service ports - MITRE T1046/T1595.001 | 1 |
| 1000002 | [BRUTE-FORCE] Burst of SSH connection attempts from single source - MITRE T1110 | 2 |
| 1000003 | [WEB-ATTACK] SQLi keyword pair UNION..SELECT in URI (triage) - OWASP A03 / T1190 | 7 |
| 1000004 | [RECON] ICMP echo request burst from single source (ping sweep) - MITRE T1595.001 | 2 |
| 1000005 | [WEB-RECON] Automated scanner User-Agent (sqlmap/Nikto/Nmap NSE/Nuclei) - MITRE T1595.002 | 1 |
| 1000006 | [WEB-ATTACK] SQLi UNION SELECT with column enumeration in URI (high fidelity) - OWASP A03 / T1190 | 6 |
| 1000007 | [WEB-ATTACK] SQLi UNION SELECT with column enumeration in POST body (high fidelity) - OWASP A03 / T1190 | 0 |
| 1000008 | [INFO] TLS session to protected segment - payload not inspectable (blind spot telemetry) | 1 |

## Top alert sources

| Source | Alerts |
|---|---|
| 127.0.0.1 | 20 |
