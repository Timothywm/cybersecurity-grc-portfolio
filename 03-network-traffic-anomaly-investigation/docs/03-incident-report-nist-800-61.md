# 03 - Incident Report (NIST SP 800-61 structure)

> Lab incident built from a synthetic capture. Structure follows the incident-handling lifecycle of NIST SP 800-61 (detection and analysis, containment, eradication and recovery, post-incident activity); Revision 3 aligns the same activities with the CSF 2.0 Detect, Respond and Recover functions. Impact statements describe what the capture shows, not real data.

| | |
|---|---|
| Incident ID | IR-LAB-2026-001 |
| Source of detection | Retrospective packet-capture analysis (no alert fired in real time) |
| Capture window | 2026-11-26 17:38:19 - 17:53:21 (UTC+7), 902 s |
| Affected systems | Web server (DMZ), application server, database server, backup server |
| Severity (lab assessment) | High: internet-facing host compromised, internal lateral movement, data staged and sent out, backup server written to |
| Confidence | High for stages 1-4 and 10 (plaintext or unique patterns); Medium for C2 and exfiltration (metadata only, TLS encrypted); Low for credential guessing (no authentication visibility) |

## 1. Executive summary
An external host (127.66.6.6) probed the public web server, injected SQL, and uploaded a PHP file that gave it command execution (T+120-223 s).
From T+300 s the web server contacted the attacker every ~29 s over TLS. From T+420 s it scanned and connected to the application, database and backup servers, which a web server has no reason to reach.
From T+540 s data left through two channels at the same time: DNS queries to an attacker-controlled domain and eight TLS uploads (~0.55 MB in total).
At T+780 s the web server opened 160 short sessions to the backup server in 24 s and then an SSH session: the network pattern that precedes destruction or encryption of backups.
No detection fired in real time; the sequence was reconstructed from the capture. The enabling condition was a flat network with no egress or east-west restrictions.

## 2. Detection and analysis
Full timeline and evidence: [02](02-investigation-timeline.md). Summary:

| # | Stage | T+ (s) | Technique | Confidence |
|---|---|---|---|---|
| 1 | Reconnaissance | 120-188 | T1595, T1595.003 | High |
| 2 | SQL injection | 189-202 | T1190 | High |
| 3 | Web shell | 204-223 | T1505.003 | High |
| 4 | C2 beaconing | 300-873 | T1071.001, T1573 | Medium |
| 5 | Internal discovery | 420-451 | T1046 | High |
| 6 | Lateral movement | 434-504 | T1021.004, T1078, T1110 | Medium / Low (credential guessing) |
| 7 | Exfiltration (DNS + TLS) | 540-850 | T1048.003, T1041, T1030 | Medium |
| 8 | Impact precursor | 780-805 | T1486, T1490 | Medium |

**Excluded as benign:** two ~8 MB database-to-backup transfers (200 s and ~620 s): internal pair, long sessions, identical size. Authorisation would be confirmed against the backup schedule.

**Not determined:** whether the SQL injection returned sensitive rows (HTTP status codes were 1,063 `200` and 30 `404`, but response bodies were not extracted), what the uploaded file contained beyond its name, what the 2 kB larger C2 responses carried, whether any login succeeded, and what happened on the backup server.

## 3. Root cause
1. **Flat network.** The web server could open sessions to the database, application and backup hosts on ports 22, 3306 and 873.
2. **No egress control** on the DMZ web server (TLS to an arbitrary external host on 8443) and no resolver policy (an internal server sending 140 unique queries to an unknown domain).
3. **File upload accepted a `.php` file** and the web server executed it from a web-reachable directory.
4. **Injectable parameter** reachable without authentication.
5. **No behavioural monitoring.** Nothing watched for a web server initiating connections, periodic outbound sessions or DNS anomalies.

## 4. Containment, eradication, recovery (recommended actions)
| Phase | Action | Rationale |
|---|---|---|
| Containment | Isolate the web server from internal segments; block 127.66.6.6 and `telemetry-cdn.example` at firewall and resolver | Stops C2, exfiltration and further lateral movement |
| Containment | Preserve a disk and memory image of the web server before changes | Evidence, and the capture cannot show file contents |
| Eradication | Remove `/uploads/img.php`, review the upload directory for other executable files, patch the injectable parameter | Removes the foothold and the entry vector |
| Eradication | Rotate credentials usable from the web host: database, application service accounts, SSH keys on app and backup | Lateral movement used SSH and database sessions |
| Recovery | Verify backup integrity from a copy the web host could not reach (offline or immutable), then restore and monitor | The backup server received 160 sessions from the compromised host |
| Recovery | Return the web server to service only after segmentation and egress rules are in place | Prevents re-compromise through the same path |

## 5. Regulatory and notification considerations
If the database held personal data, the database sessions and the exfiltration channels would require an assessment under Indonesia's UU No. 27/2022 (PDP); the law sets a notification period of 3 x 24 hours after a personal-data protection failure is established (verify the article and scope with counsel). In this lab no real personal data is involved.

## 6. Post-incident activity
Control gaps, prioritised recommendations and metrics: [05](05-lessons-learned-and-recommendations.md). Detections derived from this incident: [04](04-iocs-and-detections.md). Validation of the findings against the generator's ground truth: [06](06-validation-vs-ground-truth.md).
