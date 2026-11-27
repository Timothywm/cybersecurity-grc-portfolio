# 01 - Scenario and Attack Map

## Objective
Investigate a packet capture of a multi-stage intrusion hidden inside busy normal traffic, reconstruct the timeline from network evidence only,
and turn the findings into an incident report, detections and control recommendations (NIST SP 800-61 structure).

## Lab design
All hosts are `127.x.x.x` aliases on the loopback interface of one Kali VM, so a single `tcpdump -i lo` sees every flow with distinct addresses.
Servers are real listeners (HTTP/HTTPS with a self-signed certificate, DNS, TCP stubs for SSH, rsync and the database port). Payloads are synthetic.
The network is deliberately **flat**: any host can reach any other host. That is the root condition of the incident.

| Role | Address | Services |
|---|---|---|
| Clients (5) | 127.10.1.11-15 | browse the web server, DNS lookups |
| Web server (DMZ) | 127.10.2.10 | 80, 443 |
| Application server | 127.10.3.10 | 8080, 22 |
| Database server | 127.10.4.10 | 3306 |
| Backup server | 127.10.4.20 | 873 (rsync), 22 |
| DNS resolver | 127.10.9.53 | 53/udp |
| External attacker | 127.66.6.6 | 8443 (TLS C2) |

## Background traffic (what makes the hunt non-trivial)
- 5 clients browsing over HTTPS and HTTP with browser User-Agents, plus DNS lookups, for the full 15 minutes.
- Web-to-app API calls every ~2 s and app-to-database sessions every ~1.5 s.
- NTP/update lookups from the servers.
- Two legitimate ~8 MB database-to-backup transfers (200 s and ~620 s). They are the largest flows in the capture and act as a decoy for volume-based hunting.

## Attack stages and ATT&CK mapping
| Stage | Behaviour | ATT&CK |
|---|---|---|
| Reconnaissance | Slow port probe; wordlist content discovery | T1595, T1595.003 |
| Initial access | SQL injection with obfuscated and time-based payloads | T1190 |
| Persistence / execution | PHP file uploaded as `img.php`, commands via GET parameter | T1505.003 |
| Command and control | Periodic TLS check-ins with jitter, new session each time | T1071.001, T1573 |
| Discovery | Port sweep from the web server to app, db and backup hosts | T1046 |
| Lateral movement | SSH web to app; repeated sessions web to database | T1021.004, T1078, T1110 |
| Exfiltration | DNS tunnel plus chunked TLS uploads | T1048.003, T1071.004, T1041, T1030 |
| Impact (network precursor) | Mass writes to the backup server, then admin session | T1486, T1490 |

## Limitations
- Synthetic traffic, one capture point, one run (n = 1). Findings describe this capture, not a general benchmark.
- Loopback aliases: no MAC/TTL/ARP realism, no packet loss, no real latency.
- Database, SSH and rsync are TCP stubs. Authentication outcomes (failed vs successful login) cannot be observed, so credential-guessing claims are marked as consistent-with, not confirmed.
- TLS payloads are unreadable; conclusions about the C2 and upload channels rest on metadata (timing, size, SNI, destination).
- The analysis was written before consulting the ground-truth file; the comparison is in [06](06-validation-vs-ground-truth.md).
