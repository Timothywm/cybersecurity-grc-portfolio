#!/usr/bin/env bash
# Replay the incident pcap through the Project 02 ruleset + the Project 03 rules and count alerts per SID.
# Usage: bash tools/replay_snort.sh lab/raw/incident-01.pcap [path-to-project-02-dir]
set -u
PCAP="${1:?usage: replay_snort.sh <pcap> [project02_dir]}"
P2="${2:-$(cd "$(dirname "$0")/../.." && pwd)/02-snort-nids-threat-detection}"
P3="$(cd "$(dirname "$0")/.." && pwd)/detections/p03-snort.rules"
OUT=analysis/14-snort-replay; mkdir -p "$OUT"; rm -f "$OUT"/alert_fast.txt
cat "$P2/rules/local.rules" "$P3" > "$OUT/combined.rules"
snort -c /etc/snort/snort.lua -R "$OUT/combined.rules" --lua "$(cat "$P2/config/lab_overrides.lua")" -r "$PCAP" -k none -l "$OUT" -A alert_fast 2>&1 | tail -5
[[ -f "$OUT/alert_fast.txt" ]] || { echo "[x] no alert_fast.txt (check errors above)"; exit 1; }
{ echo "# Snort replay summary (generated $(date -Is))"; echo "alerts: $(wc -l < "$OUT/alert_fast.txt")"; echo
  echo "## alerts per SID"; grep -o '\[1:[0-9]*:[0-9]*\]' "$OUT/alert_fast.txt" | sort | uniq -c | sort -k2
  echo; echo "## first/last alert per SID"
  awk '{match($0,/\[1:[0-9]+:[0-9]+\]/); s=substr($0,RSTART,RLENGTH); if(!(s in f)) f[s]=$1; l[s]=$1} END{for(s in f) print s, f[s], l[s]}' "$OUT/alert_fast.txt" | sort
} > "$OUT/summary.txt"
cat "$OUT/summary.txt"
