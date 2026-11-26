#!/usr/bin/env bash
# Shared settings. Override any value via environment variable, e.g.  IFACE=lo ./02_run_sensor.sh
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNORT_BIN="${SNORT_BIN:-snort}"
SNORT_CONF="${SNORT_CONF:-/etc/snort/snort.lua}"
RULES="${RULES:-$PROJECT_DIR/rules/local.rules}"
OVERRIDES="${OVERRIDES:-$PROJECT_DIR/config/lab_overrides.lua}"
IFACE="${IFACE:-eth0}"
RUN_DIR="${RUN_DIR:-$HOME/snort-lab/runs}"        # raw logs stay OUTSIDE the git repo
EVIDENCE_DIR="$PROJECT_DIR/evidence"
mkdir -p "$EVIDENCE_DIR" "$RUN_DIR"
info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
# Only allow lab targets (RFC1918 / loopback). Authorization guard for attack simulations.
is_lab_ip() { [[ "$1" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.) ]]; }
