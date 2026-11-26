# Project 02 · Network Intrusion Detection & Custom Signature Engineering (Snort 3)

> Detection engineering lab: custom Snort 3 signatures mapped to **MITRE ATT&CK**, validated with true-positive, false-positive and evasion tests,
> and wrapped in the governance artefacts a GRC/security-leadership reviewer expects – **NIST SP 800-94**, threat model, risk register,
> triage runbook and **UU PDP** privacy handling.

| | |
|---|---|
| **Role simulated** | Detection engineer / security analyst reporting to GRC |
| **Engine** | Snort++ 3.12.x, passive IDS, Kali Linux (VMware), loopback (`lo`) lab |
| **Frameworks** | MITRE ATT&CK · OWASP Top 10 (A03) · NIST SP 800-94 · NIST CSF 2.0 · ISO/IEC 27001:2022 · UU No. 27/2022 (PDP) |
| **Related** | [Project 01 – SQL Injection assessment](../01-sqli-vulnerability-assessment) (the attack detected here; its remediation is the preventive control) |

## 1. Why this matters (business framing)
Preventive controls fail. A NIDS gives *time-to-detect* – but only if its limits are understood. This project does not just show that rules fire;
it measures **where detection fails** (false positives, evasion, encrypted traffic) and converts that into risk decisions.

## 2. Results at a glance
Executed on Kali Linux, Snort++ 3.12.2.0, loopback (`lo`) lab, 15 scenarios, 20 alerts, 0 unattributed.
Full per-scenario evidence: [`evidence/results.md`](evidence/results.md) · analysis: [docs/03](docs/03-fp-fn-tuning.md).

| Metric | Result |
|---|---|
| True-positive scenarios detected | **6 / 6** (100%) |
| Benign look-alike scenarios that raised an alert (false positives) | **3 / 3** (by design: collision cases, not a production FP rate) |
| Evasion scenarios that went undetected (false negatives) | **2 / 5** (40%) – low-and-slow scan, SQL keyword splitting |
| Encrypted (TLS) attack detected by payload rules | **Yes, but a loopback-topology artifact** – the TLS proxy's decrypted backend leg crossed the monitored interface (see BS1) |

**Key findings**
1. **Detection works on known shapes, and tiering contains the noise.** All six true-positive scenarios fired the intended rule. The benign search *"credit union select plan"* triggered only the low-confidence triage rule (SID 1000003) and **not** the high-fidelity rule (SID 1000006), which is the intended outcome of the two-tier design.
2. **Rate-based rules cannot separate intent from behaviour.** Legitimate SSH automation (FP1) and an uptime monitor (FP3) were indistinguishable from brute force and ping sweeps at the network layer. Suppression lists and host-level authentication logs, not tighter thresholds, are the correct fix.
3. **Two evasions succeeded, each for a structural reason.** A scan at 1 probe/second stays below the 15-per-5-seconds threshold (FN1), and `UN/**/ION SEL/**/ECT` is only reassembled by the database, not the sensor (FN4). Case variation, comment whitespace and double URL-encoding were all still caught.
4. **The encryption blind spot was not reproduced, and the reason is itself a finding.** On a single host, the TLS proxy forwarded plaintext HTTP over the same loopback interface, so the sensor inspected the decrypted leg. This demonstrates the mitigation (inspect after TLS termination) rather than the blind spot; a valid blind-spot test needs the sensor on the encrypted leg only.
5. Root-cause fixes (parameterised queries, Project 01) outperform detection; the NIDS is a *compensating* control. SSH brute force is only visible as connection **rate**, so real detection needs host auth logs and a SIEM.

## 3. Architecture
Passive sensor in front of the protected segment; alert logs kept outside the repo; evidence is redacted and hash-manifested.
Full diagram, placement rationale and STRIDE analysis of the sensor: [docs/02](docs/02-threat-model-and-architecture.md).

## 4. Detection catalogue
| SID | Detects | ATT&CK | Prio | Confidence |
|---|---|---|---|---|
| 1000001 | TCP SYN scan (rate across ports) | T1046 / T1595.001 | 2 | Medium |
| 1000002 | SSH connection burst (brute-force proxy) | T1110 | 2 | Low |
| 1000003 | SQLi keyword pair – triage tier | T1190 · OWASP A03 | 3 | Low |
| 1000004 | ICMP echo burst (ping sweep) | T1595.001 | 3 | Low |
| 1000005 | Scanner User-Agent (sqlmap/Nikto/NSE/Nuclei) | T1595.002 | 2 | High |
| 1000006 / 7 | SQLi UNION SELECT, high fidelity (URI / POST) | T1190 · OWASP A03 | 1 | High |
| 1000008 | TLS session telemetry (blind-spot metric) | – | 4 | n/a |

Rules: [`rules/local.rules`](rules/local.rules) · rationale and rev-1 → rev-2 changes: [docs/01](docs/01-detection-engineering-report.md).

## 5. Method
`Threat → hypothesis → rule → syntax gate (snort -T) → TP test → FP baseline → evasion test → tune → document`.
Every rule has evidence for all three outcomes: fires on attack, quiet on look-alike benign traffic, known evasion limits.

## 6. Reproduce (single-host loopback lab on Kali)
Attacker, target and sensor are the same Kali VM, so all traffic crosses **`lo`** (traffic to your own IP never touches `eth0`).
```bash
cd 02-snort-nids-threat-detection
./scripts/00_env_check.sh                       # baseline evidence
./scripts/01_validate_rules.sh                  # gate: must PASS (0 errors)

# Terminal 1 - sensor on loopback (-k none is set by the script: loopback checksums are unreliable)
sudo IFACE=lo ./scripts/02_run_sensor.sh
# Terminal 2 - local target services (HTTP stub on :80 stands in for DVWA; optional ssh)
sudo ./scripts/07_local_target.sh
# Terminal 3 - TLS wrapper for the blind-spot test (8443 -> 80)
sudo ./scripts/04_fp_fn_blindspot_tests.sh --start-tls-proxy
# Terminal 4 - attacks (lab targets only; asks you to type LAB)
sudo ./scripts/03_attack_simulation.sh 127.0.0.1 80          # true positives
sudo ./scripts/04_fp_fn_blindspot_tests.sh 127.0.0.1 80      # FP / evasion / blind spot

# Stop the sensor (Ctrl+C), then:
IFACE=lo ./scripts/05_collect_evidence.sh       # -> evidence/results.md
./scripts/06_sanitize_and_package.sh            # secret scan + SHA256 manifest -> git add/commit/push
```
Problems? [docs/06-troubleshooting.md](docs/06-troubleshooting.md).

## 7. Repository map
```
rules/local.rules            custom signatures (rev 2)         config/lab_overrides.lua   alert output + rate caps
scripts/                     reproducible lab pipeline          evidence/                  redacted, hashed results
docs/01 engineering report   docs/02 architecture + STRIDE      docs/03 FP/FN tuning
docs/04 NIST/ATT&CK/ISO/UU PDP   docs/05 risk register          docs/06 troubleshooting   docs/07 triage runbook
```

## 8. Limitations & next steps
- **BS1 is inconclusive for the blind-spot claim** because of the loopback topology (decrypted proxy backend leg is visible to the sensor). Re-run with the sensor restricted to the TLS leg (separate interface/namespace or a capture filter on port 8443) to demonstrate the gap.
- DVWA runs on Docker Desktop (Windows) and is **not** in this data path; the SQLi tests replay realistic DVWA-style requests against a local HTTP stub. Snort inspects the request, so detection results hold, but application responses (data returned) are not observed.
- Single sensor, loopback topology (no real network segment, no NIC/SPAN effects), synthetic traffic, small n – metrics describe this lab, not Snort in general.
- No SIEM correlation: forward alerts to Wazuh/ELK and add long-window rules (FN1) and auth-log correlation (SSH).
- Add Suricata side-by-side comparison and a PCAP regression suite in CI.
- Treat R1 (encrypted traffic) before any production use – see [risk register](docs/05-risk-register.md).

## 9. Ethics & scope
All attack simulation targets assets I own. Scripts enforce a private-address guard and explicit confirmation. Raw packet captures are never committed.
