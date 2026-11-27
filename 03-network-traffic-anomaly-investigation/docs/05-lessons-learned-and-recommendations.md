# 05 - Lessons Learned and Recommendations

## What the capture shows about control gaps
| Gap | Evidence | Control (ISO/IEC 27001:2022 Annex A / NIST CSF 2.0) |
|---|---|---|
| No segmentation between web, app, data and backup | Web server reached app:22, db:3306, backup:873 and backup:22 | A.8.22 Segregation of networks; PR.IR-01 |
| No egress filtering for the DMZ | Web server opened 29 TLS sessions to an unknown host on 8443 | A.8.20 Networks security; A.8.23 Web filtering |
| Unrestricted DNS from internal servers | App server sent 140 unique queries to an unknown domain | A.8.20; DE.CM-01 |
| Upload handling | `.php` file accepted and executed from a web-reachable path | A.8.26 Application security requirements; A.8.28 Secure coding |
| Injectable parameter | 8 SQLi probes, none blocked (responses not tabulated) | A.8.28 |
| Backup reachable from the web tier | 160 sessions web to backup in 24 s | A.8.13 Information backup |
| No behavioural detection | Nothing alerted; Project 02 signatures miss most stages | A.8.16 Monitoring activities; DE.AE-02 |
| No authentication visibility | Failed/successful DB and SSH logins not observable on the wire | A.8.15 Logging |

Mapping is illustrative; control wording should be checked against the standard before use in an audit.

## Recommendations
| Priority | Action | Effort | Owner (role) | Closes |
|---|---|---|---|---|
| P1 (days) | Contain and rebuild the web server; remove the web shell; rotate credentials reachable from it | Low | IR lead | Foothold |
| P1 | Verify backups from an unreachable copy before restoring | Low | Infrastructure | Impact |
| P1 | Default-deny egress for the DMZ; allow only required destinations | Low | Network | C2, exfiltration |
| P2 (weeks) | Three zones with default-deny between them: DMZ, application, data and backup. Allowed paths only: internet to web:443, web to app:8080, app to db:3306. Backup pulls from the data zone; nothing in the DMZ may reach it | Medium | Network / Architect | Lateral movement, impact |
| P2 | Internal resolver only; block direct external DNS; alert on query length, uniqueness and new domains | Medium | Network / SOC | DNS tunnel |
| P2 | Upload hardening: extension and content allowlist, store outside the web root, no script execution there; parameterised queries (see Project 01) | Medium | Application owner | Entry vector |
| P3 (quarter) | Deploy the policy rules (1000101/102/106) as a baseline and tune; add flow logs and beacon analytics (interval and jitter) | Medium | SOC / Detection | Detection gap |
| P3 | Forward web, database, SSH and DNS logs to a SIEM so authentication outcomes can be correlated with network events | Medium | SOC | Visibility |
| P3 | Immutable or offline backup copies; tabletop exercise using this timeline | Medium | CISO / Infrastructure | Impact, readiness |

## Risk statement for management
A compromise of the single internet-facing host currently gives access to every tier, including the data that must survive an attack (backups). Segmentation and egress control reduce that to a contained web-tier incident. Detection alone would not have prevented it: the signatures in Project 02 would have caught only part of stage 2.

## Metrics from this capture
| Metric | Value |
|---|---|
| Dwell time observed (first probe to end of capture) | 782 s (13 min) |
| Real-time alerts raised | 0 |
| Stages reconstructed from network data | 11 attack stages plus 1 benign activity (see [06](06-validation-vs-ground-truth.md)) |
| Exfiltrated volume (observed) | ~0.55 MB TLS + up to ~4.5 KB DNS, about 3% of the benign backup volume |
| Beacon period | 28.6 s mean, CV 22%, 20.2-40.2 s |

## Lessons
1. **Volume is a poor hunting signal.** The biggest flows were benign; the harmful exfiltration was ~3% of that size.
2. **Direction and role beat signatures.** A web server initiating connections is anomalous regardless of payload or encryption.
3. **Periodicity survives encryption.** Interval statistics identified the C2 without reading a byte of payload.
4. **Architecture documentation is a detection asset.** Policy rules need a defined "allowed" model.
5. **Know the evidence limits.** The capture cannot show file contents, login outcomes or host actions; the report separates confirmed findings from inferences.
