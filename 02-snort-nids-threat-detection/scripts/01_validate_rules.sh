#!/usr/bin/env bash
# Gate 1 of the detection pipeline: the rule file must load with ZERO errors before any test.
source "$(dirname "$0")/common.sh"
OUT="$EVIDENCE_DIR/01-rule-validation.txt"
info "Validating $RULES against $SNORT_CONF"
{
  echo "# Rule validation - $(date -Is)"; "$SNORT_BIN" -V 2>&1 | head -3
  "$SNORT_BIN" -c "$SNORT_CONF" -R "$RULES" --lua "$(cat "$OVERRIDES")" --warn-rules -T 2>&1
} | tee "$OUT"
if grep -q "successfully validated" "$OUT"; then ok "PASS - configuration validated"; else die "FAIL - see $OUT (paste the first ERROR line to get help)"; fi
