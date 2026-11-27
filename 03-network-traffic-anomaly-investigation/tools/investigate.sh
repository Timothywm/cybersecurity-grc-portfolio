#!/usr/bin/env bash
# Phase 3 - deep-dive on the triage hypotheses. Usage: bash tools/investigate.sh lab/raw/incident-01.pcap
set -u
P="${1:?usage: investigate.sh <pcap>}"; O=analysis; mkdir -p "$O"
WEB=127.10.2.10; APP=127.10.3.10; ATK=127.66.6.6
first_last() { awk '{k=$2":"$3; c[k]++; if(!(k in f)) f[k]=$1; l[k]=$1} END{for(k in c) printf "%-20s n=%-4d first=%7.1fs last=%7.1fs\n",k,c[k],f[k],l[k]}' | sort; }

# 07 beacon timing: web -> external TLS sessions (time, delta)
tshark -r "$P" -Y "tls.handshake.type==1 && ip.src==$WEB && ip.dst==$ATK" -T fields -e frame.time_relative \
 | awk '{printf "%7.1f", $1; if (NR>1) printf "  +%.1fs", $1-p; printf "\n"; p=$1}' > "$O/07-web-to-ext-tls-timing.txt"
# 08 size of each TCP conversation on 8443
tshark -r "$P" -q -z conv,tcp,tcp.port==8443 > "$O/08-tcp-8443-conversations.txt"
# 09 DNS from app server: sample, unique names, parent domain, time span
{ echo "## first 12 queries"; tshark -r "$P" -Y "dns.flags.response==0 && ip.src==$APP" -T fields -e frame.time_relative -e dns.qry.name -e dns.qry.type | head -12
  echo "## unique names"; tshark -r "$P" -Y "dns.flags.response==0 && ip.src==$APP" -T fields -e dns.qry.name | sort -u | wc -l
  echo "## parent domains"; tshark -r "$P" -Y "dns.flags.response==0 && ip.src==$APP" -T fields -e dns.qry.name | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c
  echo "## time span"; tshark -r "$P" -Y "dns.flags.response==0 && ip.src==$APP && dns.qry.name contains telemetry" -T fields -e frame.time_relative | sed -n '1p;$p'; } > "$O/09-dns-app-server.txt"
# 10 HTTP requests from the external host (plaintext)
tshark -r "$P" -Y "http.request && ip.src==$ATK" -T fields -e frame.time_relative -e http.request.method -e http.request.uri | cut -c1-150 > "$O/10-http-from-external.txt"
# 11 external host: SYN targets (port probing)  /  12 web server: first contact with internal hosts
tshark -r "$P" -Y "ip.src==$ATK && ip.dst==$WEB && tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.time_relative -e ip.dst -e tcp.dstport | first_last > "$O/11-external-syn-targets.txt"
tshark -r "$P" -Y "ip.src==$WEB && tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst!=$ATK" -T fields -e frame.time_relative -e ip.dst -e tcp.dstport | first_last > "$O/12-web-outbound-internal.txt"
# 13 web -> backup/db session counts per minute
tshark -r "$P" -Y "ip.src==$WEB && (ip.dst==127.10.4.20 || ip.dst==127.10.4.10) && tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.time_relative -e ip.dst -e tcp.dstport \
 | awk '{m=int($1/60); k=m" "$2":"$3; c[k]++} END{for(k in c) print k, c[k]}' | sort -n > "$O/13-web-to-db-backup-per-minute.txt"
echo "[+] done"; wc -l "$O"/0[7-9]* "$O"/1[0-3]*
