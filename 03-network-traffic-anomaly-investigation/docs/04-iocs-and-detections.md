# 04 - Indicators, Detections and Hunt Queries

## Indicators of compromise (lab-scoped)
| Type | Value | Context | Shelf life |
|---|---|---|---|
| IP | 127.66.6.6 | Scanning, SQLi, web shell, C2 and upload destination | Short |
| SNI / host | `cdn-assets.telemetry-cdn.example` | TLS channel (check-ins and uploads) | Short |
| Domain | `*.telemetry-cdn.example` | DNS tunnel; 140 unique 79-character names | Short |
| URI | `/upload.php` (POST, multipart, `.php` filename) | Web shell upload | Medium |
| URI | `/uploads/img.php?c=<cmd>` | Web shell execution | Medium |
| TCP | web (127.10.2.10) to 127.10.4.20:873, 160 sessions in 24 s | Backup tampering precursor | Behavioural |
| TCP | web to 127.10.3.10:22, 127.10.4.10:3306, 127.10.4.20:22/873 | Lateral movement | Behavioural |

IPs and domains expire fast. The durable detections are behavioural: **a web server that initiates connections**, periodic outbound sessions, DNS length/uniqueness anomalies and short-session bursts to a backup service.

## Detection rules
[`detections/p03-snort.rules`](../detections/p03-snort.rules), SIDs 1000101-1000108.

| SID | Type | Detects | Stage | Replay alerts |
|---|---|---|---|---|
| 1000101 | Policy | Web server SYN to app/db/backup service ports | Lateral movement | 188 |
| 1000102 | Policy | Web server SYN to any address outside 127.10.0.0/16 | C2, exfiltration | 29 |
| 1000103 | IOC | Attacker SNI in a TLS ClientHello | C2, exfiltration | 0 (covered by 1000102) |
| 1000104 | IOC | Tunnel domain in a DNS query | DNS tunnel | 140 |
| 1000105 | Heuristic | 20+ DNS queries over 80 bytes of payload per minute from one host | DNS tunnel | 120 |
| 1000106 | Heuristic | 40+ SYNs per minute to the backup rsync port | Impact precursor | 120 |
| 1000107 | IOC | `/uploads/*.php?c=` request | Web shell | 6 |
| 1000108 | Heuristic | Multipart upload with `.php` filename | Web shell | 1 |

Policy rules need no signature and survive attacker changes; they only work because the intended architecture is defined (web tier talks to the app tier, nothing else). That is why architecture documentation is a detection asset.

## Coverage of the Project 02 and Project 03 rulesets (measured replay)
Replay command (`analysis/14-snort-replay/summary.txt`, **609 total alerts**):
```bash
bash tools/replay_snort.sh lab/raw/incident-01.pcap
```
The replay runs the Project 02 and Project 03 rules together.

| Stage | Rule(s) evaluated | Measured replay result |
|---|---|---|
| Slow port probe (1 SYN / 2.4 s) | P02 `1000001` (15 SYN in 5 s) | **Miss** (peak ~2-3 SYNs per 5 s) |
| SQLi `uNiOn SeLeCt`, `/**/` UNION | P02 `1000003`, `1000006` | **Detect** (`1000003`: 2 alerts, `1000006`: 2 alerts) |
| SQLi `UN/**/ION SEL/**/ECT` | P02 `1000003`, `1000006` | **Miss** (known evasion FN4) |
| SQLi `'`, `OR '1'='1`, `ORDER BY`, `SLEEP()` | P02 ruleset | **Miss** (not covered by UNION signatures) |
| Web shell upload & execution | P03 `1000108`, `1000107` | **Detect** (`1000108`: 1 alert, `1000107`: 6 alerts) |
| Outbound C2 & TLS exfiltration (29 sessions) | P03 `1000102`, `1000103` | **Detect** (`1000102`: 29 alerts; `1000103`: 0 alerts) |
| Internal sweep & lateral movement | P03 `1000101` | **Detect** (`1000101`: 188 alerts across internal probes/sessions) |
| DNS tunnel (140 unique 79-char queries) | P03 `1000104`, `1000105` | **Detect** (`1000104`: 140 alerts, `1000105`: 120 alerts) |
| Backup rsync burst (160 SYNs in 24 s) | P02 `1000001`, P03 `1000106` | **Detect** (`1000001`: 1 alert, `1000106`: 120 alerts) |

## Hunt queries (tshark)
```bash
P=lab/raw/incident-01.pcap
# servers that initiate connections to hosts outside the internal range
tshark -r $P -Y 'ip.src==127.10.2.10 && tcp.flags.syn==1 && tcp.flags.ack==0 && !(ip.dst==127.10.0.0/16)' -T fields -e frame.time_relative -e ip.dst -e tcp.dstport
# DNS names unusually long, per source
tshark -r $P -Y 'dns.flags.response==0 && len(dns.qry.name) > 50' -T fields -e ip.src -e dns.qry.name | cut -c1-120 | sort | uniq -c | sort -rn | head
# first-seen internal contacts from the DMZ host
tshark -r $P -Y 'ip.src==127.10.2.10 && tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.time_relative -e ip.dst -e tcp.dstport
# periodicity of a suspect destination
python3 tools/beacon_stats.py $P 127.10.2.10 127.66.6.6 8443
```