# evidence/
Screenshots referenced by the documents. Terminals show only lab data (synthetic 127.x addresses).

| File | Shows |
|---|---|
| 01-capture-tcpdump-running.png | tcpdump listening on `lo` with the capture filter |
| 02-generator-started.png | traffic generator started (15 min timeline) |
| 03-generator-done.png | generator finished |
| 04-pcap-capinfos.png | `capinfos` and SHA-256 of the capture (41,642 packets, 902 s) |
| 05-protocol-hierarchy.png | protocol hierarchy and IPv4 conversations |
| 08-beacon-timing.png | timing and size of TLS sessions to the external host |
| 09-dns-tunnel-queries.png | DNS names from the application server |
| 10-snort-replay.png | alerts per SID from replaying the capture through Snort |
| 11-validation.png | output of `tools/validate_findings.py` |
