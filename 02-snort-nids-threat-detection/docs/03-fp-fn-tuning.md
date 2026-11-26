# 03 · False-Positive / False-Negative Analysis and Tuning

> Source: [`evidence/results.md`](../evidence/results.md) (Snort++ 3.12.2.0, loopback lab, 15 scenarios, 20 alerts, 0 unattributed).
> The **Expected** column is the hypothesis written *before* testing; **Observed** is the measured outcome.
> One run per scenario (n = 1): results describe this lab, not statistical performance.

## 0. True positives – does each rule fire on the attack it targets?

| ID | Scenario | Expected SID(s) | Observed | Verdict |
|---|---|---|---|---|
| TP1 | ICMP echo burst (10 pings / 2 s) | 1000004 | 1000004 fired (1 alert, capped by `event_filter`) | Detected |
| TP2 | Nmap SYN scan, ports 1–1024 | 1000001 | 1000001 fired (1 alert) | Detected |
| TP3 | 12 SSH connection attempts in ~4 s | 1000002 | 1000002 fired (1 alert) | Detected |
| TP4 | SQLi `UNION SELECT user,password FROM users` | 1000003, 1000006 | Both fired | Detected |
| TP5 | SQLi `UNION ALL SELECT NULL,NULL` | 1000003, 1000006 | Both fired | Detected |
| TP6 | `sqlmap` User-Agent | 1000005 | 1000005 fired | Detected |

**Result: 6/6 detected.** One alert per rate-based scenario is expected: the `event_filter` limit (1 per 60 s per source) suppresses per-packet duplicates.

## 1. False positives – benign traffic that looks malicious

| ID | Benign activity | Rule(s) at risk | Expected | Observed | Root cause | Tuning action |
|---|---|---|---|---|---|---|
| FP1 | 8 legitimate SSH sessions in 4 s (automation, Ansible, backups) | 1000002 | Alert | **Alert fired** (SID 1000002) | Network layer cannot distinguish success from failure inside the encrypted SSH channel | `suppress` known admin/automation hosts; raise count; move real detection to auth logs (fail2ban/SIEM) |
| FP2 | Search "credit union select plan" | 1000003 | Alert (broad) / no alert (1000006) | **Only 1000003 fired; 1000006 stayed silent** | Keyword-pair rule has no SQL context | Keep 1000003 at priority 3 (triage); alert humans only on 1000006/7 |
| FP3 | Uptime monitor pinging every 0.2 s | 1000004 | Alert | **Alert fired** (SID 1000004) | Same traffic shape as a ping sweep | `suppress` monitoring host; or raise threshold |

**Result: 3/3 benign scenarios raised an alert.** These cases were chosen to collide with the rules, so this is a stress test, not a production false-positive rate. FP2 confirms the tiering works: the keyword collision reached only the triage tier. FP1 and FP3 show that rate rules fire on *behaviour*, regardless of intent.

**Takeaway:** an alert is a *hypothesis*, not a verdict. Priority tiers + suppression convert noisy detections into a triage queue.

Tuning snippet (activate in `config/lab_overrides.lua`; see also `config/suppress_example.lua`):
```lua
suppress = { { gid = 1, sid = 1000002, track = 'by_src', ip = '192.168.57.10' } }
```

## 2. False negatives – evasion attempts

| ID | Technique | Rule | Expected | Observed | Why | Compensating control |
|---|---|---|---|---|---|---|
| FN1 | Low-and-slow scan (1 probe/s) | 1000001 | Missed | **Missed** (0 alerts) | 5 SYNs per 5 s < threshold 15 | Longer-window correlation in SIEM (e.g. 100 ports / 10 min), built-in `port_scan` inspector (unique-port logic) |
| FN2 | Mixed case `uNiOn SeLeCt` | 1000006 | Detected | **Detected** (1000003 + 1000006) | `/i` flag | – |
| FN3 | `UNION/**/SELECT` | 1000006 | Detected | **Detected** (1000003 + 1000006) | Regex tolerates comment whitespace | – |
| FN4 | `UN/**/ION SEL/**/ECT` | 1000006 | **Missed** | **Missed** (0 alerts, neither tier fired) | Keyword split by comment is only reassembled by the database | WAF with SQL tokenizer (libinjection), parameterized queries (root fix – see Project 01) |
| FN5 | Double URL-encoding | 1000006 | Missed (verify) | **Detected** (1000003 + 1000006); hypothesis rejected | The HTTP inspector's normalization reconstructed the keywords from the double-encoded input (consistent with repeated percent-decoding; exact decoding depth not verified) | Keep normalization enabled; do not assume it covers other encodings (e.g. UTF-8/%u variants untested) |

**Result: 2/5 evasions succeeded (40%), 3/5 were caught.** Both successes exploit a structural limit rather than a rule typo: a time-window threshold (FN1) and a keyword only reassembled by the database (FN4). FN5 was a hypothesis the data rejected, which is why it was tested.

**Takeaway:** signatures catch known shapes; evasion moves the attacker to what the sensor does not normalize. Root-cause fixes
(prepared statements, input validation) beat detection – NIDS is a **compensating** control.

## 3. Blind spot – encryption

| ID | Test | Expected | Observed |
|---|---|---|---|
| BS1 | Same UNION SELECT payload over TLS (port 8443 via socat) | Only telemetry SID 1000008; **no** SQLi alert | **1000008, 1000003 and 1000006 all fired** – attack still detected |

**Why the blind spot did not appear (loopback topology artifact).** The `socat` proxy terminates TLS on port 8443 and forwards the **decrypted**
HTTP request to the backend on `127.0.0.1:80`. In this single-host lab both legs travel over the same interface (`lo`), and the sensor listens on `lo`.
It therefore saw two flows for one request:

```
client --TLS (8443, encrypted)--> socat --plain HTTP (80, decrypted)--> backend
          ^ SID 1000008 fired                ^ SID 1000003 / 1000006 fired
```

The TLS leg behaved as predicted: only telemetry (1000008), no payload visibility. The SQLi alerts came from the backend leg, which carries
plaintext. In a real deployment the proxy and backend are usually separate (or the sensor sits in front of the proxy), so the sensor would
see **only** the encrypted leg and the attack would pass undetected.

**Conclusion.** BS1 does not disprove the blind spot; it shows that **detection is possible wherever traffic is visible in plaintext**, which is exactly the
mitigation in option (a) below. The test as run is **inconclusive for the blind-spot claim**. To demonstrate it, restrict the sensor to the encrypted leg
(for example, place the backend in a separate network namespace/interface, or capture only port 8443 with a filter supported by your DAQ setup) and re-run BS1.

Options and trade-offs: (a) TLS termination at a reverse proxy/WAF with inspection *after* decryption (privacy and key-management cost); (b) host-based detection
(web access logs, application logs → SIEM); (c) metadata analytics (SNI, certificate reputation) – privacy-preserving but lower fidelity.
**Decision for this lab:** record R1 (encrypted traffic) in the risk register as *partially accepted*; BS1 re-test is a listed follow-up.

## 4. Detection-quality metrics (this run)

| Metric | Definition | Value |
|---|---|---|
| True-positive rate | detected TP scenarios / total TP scenarios | **6 / 6 = 100%** |
| Benign scenarios alerting | benign scenarios raising a non-telemetry alert / total | **3 / 3** (collision cases by design) |
| Evasion success rate | FN scenarios not detected / total FN scenarios | **2 / 5 = 40%** |
| Unattributed alerts | alerts outside any scenario window | **0** |

Interpret these as *this lab's* coverage, not a product benchmark: n = 1 per scenario, synthetic traffic, single source address (`127.0.0.1`) because of the loopback topology.
