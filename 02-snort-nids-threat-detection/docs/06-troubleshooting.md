# 06 · Troubleshooting & Known Pitfalls (Snort 3 on Kali / VMware)

| Symptom | Likely cause | Fix |
|---|---|---|
| `snort -T` prints `ERROR: ... local.rules` | Snort 2 syntax in a Snort 3 rule | Snort 3 differences: `flags:S*` means *any*; options like `nocase`, `distance` are comma-separated inside `content`; buffers are *sticky* (`http_uri;` **before** `content`) |
| `ERROR: unknown variable $HOME_NET` | Config lacks the variable | Use stock `/etc/snort/snort.lua` (defines `HOME_NET`), or set `HOME_NET = '192.168.57.0/24'` there |
| Sensor runs, **zero alerts**, attacking from Kali to its own IP | Traffic to your own IP travels on **`lo`**, not `eth0` | Attack from another host, or run the sensor with `IFACE=lo` / `-i any` |
| Zero alerts even from another host | VMware adapter doesn't deliver the traffic / checksum offload | Check `ip -s link`; keep `-k none` (script does); disable offload (`ethtool -K eth0 rx off tx off`); use Bridged/Host-only adapter |
| No `alert_fast.txt` in log dir | `alert_fast = { file = true }` not applied | Confirm `config/lab_overrides.lua` is loaded (script passes it with `--lua`); console output is also saved in `console.log` |
| DVWA not seen by HTTP rules | Docker port mapped to e.g. 8080 / HTTP inspector not enabled on that port | `docker ps`; use `$HTTP_PORTS` default (includes 80, 8080); check `http_inspect` in `snort.lua` |
| TLS test shows no 1000008 | `ssl` inspector off or proxy not running | `04_fp_fn_blindspot_tests.sh --start-tls-proxy` on target; verify `ss -tlnp | grep 8443` |
| Running the lab on one host | Self-traffic is on `lo`; checksum offload makes packets look corrupt | `IFACE=lo`, keep `-k none` (script sets it), start the stub with `07_local_target.sh` |
| `permission denied` | Needs raw socket | `sudo` for sensor and for `nmap -sS` |
| Attack timeline doesn't match alerts | Clock skew between attacker and sensor | Sync NTP, or `SKEW=<sec> ./05_collect_evidence.sh` |
| Alert flood | Rate rules alert per packet above threshold | `event_filter` in `lab_overrides.lua` (already enabled) |

Snort version check: `snort -V` (expected `Snort++ 3.12.x`). Config check: `scripts/01_validate_rules.sh`.
