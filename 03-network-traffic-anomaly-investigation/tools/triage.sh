#!/usr/bin/env bash
# Phase 2 - blind triage. Usage: bash tools/triage.sh lab/raw/incident-01.pcap
set -u
P="${1:?usage: triage.sh <pcap>}"; O=analysis; mkdir -p "$O"
tshark -r "$P" -q -z io,phs   > "$O/01-protocol-hierarchy.txt"
tshark -r "$P" -q -z conv,ip  > "$O/02-conversations-ip.txt"
tshark -r "$P" -q -z io,stat,60 > "$O/03-traffic-per-minute.txt"
tshark -r "$P" -Y 'http.request' -T fields -e ip.src -e ip.dst -e tcp.dstport -e http.user_agent \
  | sort | uniq -c | sort -rn | head -30 > "$O/04-http-requests.txt"
tshark -r "$P" -Y 'tls.handshake.type==1' -T fields -e ip.src -e ip.dst -e tcp.dstport -e tls.handshake.extensions_server_name \
  | sort | uniq -c | sort -rn | head -30 > "$O/05-tls-clienthello.txt"
tshark -r "$P" -Y 'dns.flags.response==0' -T fields -e ip.src -e dns.qry.name \
  | awk '{print $1, length($2)}' | sort | uniq -c | sort -rn | head -30 > "$O/06-dns-source-and-name-length.txt"
echo "[+] done -> $O/"; ls -l "$O"
