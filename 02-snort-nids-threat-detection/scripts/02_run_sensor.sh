#!/usr/bin/env bash
# Run Snort 3 as a passive NIDS. Usage: sudo IFACE=eth0 ./02_run_sensor.sh   (Ctrl+C to stop)
#   CAPTURE=1  -> also record a raw pcap (for replay/regression). Contains payloads => see docs/04 (privacy).
source "$(dirname "$0")/common.sh"
[[ $EUID -eq 0 ]] || die "Run as root (sudo) to sniff $IFACE"
STAMP="$(date +%Y%m%d-%H%M%S)"; LOGDIR="$RUN_DIR/$STAMP"; mkdir -p "$LOGDIR"
ln -sfn "$LOGDIR" "$RUN_DIR/latest"
if command -v ethtool >/dev/null; then ethtool -K "$IFACE" rx off tx off gro off lro off tso off gso off 2>/dev/null || warn "Could not disable offload on $IFACE"; fi
if [[ "${CAPTURE:-0}" == "1" ]]; then tcpdump -i "$IFACE" -s 0 -w "$LOGDIR/session.pcap" >/dev/null 2>&1 & TCPD=$!; trap 'kill $TCPD 2>/dev/null' EXIT; info "pcap -> $LOGDIR/session.pcap"; fi
info "Sensor on $IFACE | logs: $LOGDIR  (symlink: $RUN_DIR/latest)"
# -k none : do not drop packets with bad checksums (VM/NIC offload makes locally generated packets look 'bad')
"$SNORT_BIN" -c "$SNORT_CONF" -R "$RULES" --lua "$(cat "$OVERRIDES")" -i "$IFACE" -k none -s 65535 -l "$LOGDIR" -A alert_fast 2>&1 | tee "$LOGDIR/console.log"
