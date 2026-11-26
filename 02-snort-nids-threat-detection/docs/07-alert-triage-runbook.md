# 07 · Alert Triage Runbook (SOC L1 → L2)

Principle: **an alert is a hypothesis.** Confirm with a second data source before declaring an incident.

| Priority | Meaning | Target response |
|---|---|---|
| 1 | High-fidelity attack pattern | Triage now (≤ 15 min), assume malicious until disproved |
| 2 | Suspicious behaviour | Triage same business day |
| 3 | Low-confidence signal | Batch review; look for repetition / correlation |
| 4 | Telemetry | Metrics only (coverage dashboard) |

## Per-alert checklist
| SID | Confirm with | Benign explanations | Escalate (L2) if | Containment (after approval) |
|---|---|---|---|---|
| 1000001 / 1000004 | Source asset inventory; firewall/flow logs; is source internal? | Vulnerability scanner, monitoring, load test | Unknown source, or followed by 1000002/1000006 from same IP | Block source at firewall; add to watchlist |
| 1000002 | `/var/log/auth.log` / `journalctl -u ssh`: failed vs accepted logins | Automation/backup, jump host | Many *Failed password* then *Accepted* from same IP | Block IP, force credential reset, enable key-only auth/fail2ban |
| 1000003 | Web access log + app log for the request, response status/size | Search text containing both words | Same source also triggers 1000006 | – |
| 1000005 | Source IP, request volume, targets | Authorised scan window | Outside change window | Block source, review WAF rules |
| 1000006 / 1000007 | Response size/time (data returned?), DB error logs, WAF logs | Security test by the team | Response indicates data returned, or successful auth after | Block source, WAF virtual patch, **start incident response**, check for data exposure (UU PDP 3×24 h clock) |

## Closing an alert
Record: verdict (TP / benign / FP), evidence, action, and **rule feedback** (suppress? tune? new rule?). Feedback closes the detection-engineering loop ([01 §1](01-detection-engineering-report.md)).
