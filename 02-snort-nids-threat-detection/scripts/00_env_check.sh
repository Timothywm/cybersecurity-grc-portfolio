#!/usr/bin/env bash
# Records the lab baseline (evidence for "environment & scope"). Run on the Kali sensor.
source "$(dirname "$0")/common.sh"
OUT="$EVIDENCE_DIR/00-environment.txt"
{
  echo "# Environment baseline - $(date -Is)"
  echo; echo "## OS";            . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}"; uname -r
  echo; echo "## Snort";         "$SNORT_BIN" -V 2>&1 | head -8
  echo; echo "## Interfaces";    ip -brief addr
  echo; echo "## NIC offload on $IFACE (should be OFF for accurate checksums)"
  (ethtool -k "$IFACE" 2>/dev/null | grep -E 'rx-checksumming|tx-checksumming|generic-receive-offload|tcp-segmentation-offload') || echo "ethtool not available"
  echo; echo "## Listening services (targets in scope)"; ss -tlnp 2>/dev/null | head -20
  echo; echo "## Docker containers"; (docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null) || echo "docker not available"
  echo; echo "## Snort config files"; ls -l "$SNORT_CONF" "$RULES" 2>&1
} | tee "$OUT"
ok "Saved to $OUT"
