# Project 03 - Network Traffic Anomaly Investigation

> Incident analysis of a multi-stage intrusion hidden in busy normal traffic. From a packet capture alone: reconstruct the timeline, classify what is benign,
> prove command-and-control and exfiltration from metadata, and turn the findings into an incident report (NIST SP 800-61), detections and control recommendations.

| | |
|---|---|
| **Role simulated** | SOC analyst (tier 1/2) handing findings to GRC |
| **Tools** | Wireshark, tshark, tcpdump, Python, Snort 3 |
| **Frameworks** | MITRE ATT&CK, NIST SP 800-61, NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, UU No. 27/2022 (PDP) |
| **Related** | [Project 01](../01-sqli-vulnerability-assessment) (the injectable app) · [Project 02](../02-snort-nids-threat-detection) (signature coverage tested here) |

## Scenario
A 15-minute capture of an internet-facing web server on a flat network: five clients browsing over HTTPS, API and database traffic, DNS, and two legitimate 8 MB backups.
Inside it: recon, SQL injection with obfuscated payloads, a web shell, TLS beaconing with jitter, internal discovery, lateral movement, exfiltration over DNS and TLS, and a burst of writes to the backup server.
Details and ATT&CK mapping: [docs/01](docs/01-scenario-and-attack-map.md).

## Key findings
1. **The decoy was the biggest flow.** rsync is 62% of all bytes. Both large transfers are internal, scheduled-looking database-to-backup jobs; the real exfiltration is ~0.55 MB, about 3% of that volume.
2. **C2 identified without reading payload.** 21 TLS check-ins from the web server to one external host: mean 28.6 s, standard deviation 6.4 s (CV 22%), constant ~2.7 kB upstream. Eight larger uploads (62-71 kB) share the same destination and are separable by size.
3. **DNS tunnelling is visible in names alone.** 140 unique 79-character names under one domain from a server that normally makes 22 NTP/update lookups; client names are 7-25 characters.
4. **Role violations are the strongest signal.** A web server initiating connections to the database, backup server and the internet needs no signature. 160 sessions to the backup rsync port in 24 s, against the legitimate job's two long sessions.
5. **Project 02's signatures cover a fraction of this attack** (slow scan and key SQLi evasions pass through; replay results in [docs/04](docs/04-iocs-and-detections.md)). Behavioural and policy rules are added in `detections/`.

## Deliverables
| Document | Content |
|---|---|
| [docs/01](docs/01-scenario-and-attack-map.md) | Lab design, traffic mix, ATT&CK map, limitations |
| [docs/02](docs/02-investigation-timeline.md) | Baseline, decoy analysis, timeline with evidence references |
| [docs/03](docs/03-incident-report-nist-800-61.md) | Incident report: summary, root cause, containment/recovery, notification |
| [docs/04](docs/04-iocs-and-detections.md) | IOCs, Snort rules, coverage of Project 02, hunt queries |
| [docs/05](docs/05-lessons-learned-and-recommendations.md) | Control gaps (ISO 27001 / CSF), prioritised recommendations, metrics |
| [docs/06](docs/06-validation-vs-ground-truth.md) | Findings compared with the generator's ground truth (generated) |

## Reproduce
```bash
# 1. record (terminal 1), then generate (terminal 2); ~16 min real time
sudo tcpdump -i lo -s 0 -nn -U -Z root -w lab/raw/incident-01.pcap 'net 127.10.0.0/16 or net 127.66.0.0/16'
sudo python3 tools/gen_traffic.py
# 2. investigate
bash tools/triage.sh lab/raw/incident-01.pcap
bash tools/investigate.sh lab/raw/incident-01.pcap
python3 tools/beacon_stats.py lab/raw/incident-01.pcap 127.10.2.10 127.66.6.6 8443
# 3. test detections, then compare with ground truth (only after writing up findings)
bash tools/replay_snort.sh lab/raw/incident-01.pcap
python3 tools/validate_findings.py --pcap lab/raw/incident-01.pcap --gt lab/ground_truth.csv --findings tools/findings.csv
```

## Repository map
```
tools/        gen_traffic.py  triage.sh  investigate.sh  beacon_stats.py  replay_snort.sh  validate_findings.py  findings.csv
analysis/     tshark outputs (01-13) and Snort replay results (14)
detections/   p03-snort.rules
docs/         01-06            evidence/   screenshots
lab/          (git-ignored) raw pcap, ground truth, certificate
```

## Limitations
- Synthetic traffic on loopback aliases, one capture point, one run. No MAC/TTL realism or packet loss.
- Database, SSH and rsync are TCP stubs: login outcomes and file actions are not observable, so credential guessing is reported as "consistent with".
- TLS content is unreadable; C2 and exfiltration conclusions rest on timing, size, destination and SNI.
- The ground-truth file was not opened until the write-up was finished; the traffic generator is part of this repository.

## Ethics and scope
All traffic is generated between processes on one VM that I own. Payloads are inert. Raw captures are not published.
