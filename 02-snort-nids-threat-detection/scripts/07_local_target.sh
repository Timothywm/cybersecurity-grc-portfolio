#!/usr/bin/env bash
# Single-host loopback lab: starts the local services that the simulated attacks talk to.
#   - HTTP stub on 127.0.0.1:80  (stands in for DVWA; Snort inspects the REQUEST, the 404 response is irrelevant)
#   - SSH on :22 is optional (SYNs are counted even if the port is closed)
# Usage: sudo ./07_local_target.sh      (Ctrl+C to stop)
source "$(dirname "$0")/common.sh"
[[ $EUID -eq 0 ]] || die "Port 80 needs root"
systemctl start ssh 2>/dev/null && ok "ssh service started" || warn "ssh not started (optional)"
D="$RUN_DIR/www"; mkdir -p "$D"; echo "<h1>lab target</h1>" > "$D/index.html"
info "HTTP stub on 127.0.0.1:80 (serving $D)"
cd "$D" && exec python3 -m http.server 80 --bind 127.0.0.1
