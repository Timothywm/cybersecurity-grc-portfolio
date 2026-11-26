#!/usr/bin/env bash
# Run on the sensor after the tests: correlates alerts with the attack timeline -> evidence/results.md
# Copy attack-timeline.csv from the attacker host into evidence/ first (if it ran elsewhere).
source "$(dirname "$0")/common.sh"
RUN="${1:-$RUN_DIR/latest}"; [[ -f "$RUN/alert_fast.txt" ]] || die "No $RUN/alert_fast.txt - did Snort write alerts? (see docs/06-troubleshooting.md)"
[[ -f "$EVIDENCE_DIR/attack-timeline.csv" ]] || die "Missing evidence/attack-timeline.csv"
python3 -I "$PROJECT_DIR/scripts/analyze_alerts.py" --alerts "$RUN/alert_fast.txt" --timeline "$EVIDENCE_DIR/attack-timeline.csv" \
  --rules "$RULES" --out "$EVIDENCE_DIR/results.md" ${SKEW:+--skew "$SKEW"}
cp "$RUN/alert_fast.txt" "$EVIDENCE_DIR/alert_fast.raw.txt"
ok "Next: review evidence/results.md, then run scripts/06_sanitize_and_package.sh"
