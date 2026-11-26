#!/usr/bin/env bash
# Pre-push gate: privacy/secret scan + integrity manifest. Raw pcaps and run logs never enter the repo.
source "$(dirname "$0")/common.sh"
cd "$EVIDENCE_DIR"
[[ -f alert_fast.raw.txt ]] && sed -E 's/(PHPSESSID=)[A-Za-z0-9]+/\1<redacted>/g' alert_fast.raw.txt > alert_fast.sample.txt && rm alert_fast.raw.txt
FOUND=0
for pat in 'PHPSESSID=[A-Za-z0-9]{8,}' 'password=[^&" ]+' 'ghp_[A-Za-z0-9]{20,}' 'BEGIN (RSA|OPENSSH|PRIVATE) KEY' 'AKIA[0-9A-Z]{16}'; do
  if grep -rEI --exclude=SHA256SUMS -n "$pat" "$PROJECT_DIR" --include='*.txt' --include='*.md' --include='*.csv' --include='*.log' 2>/dev/null | grep -v 'password=\[' | head -3 | grep .; then FOUND=1; fi
done
find "$PROJECT_DIR" -name '*.pcap*' -o -name '*.pcapng' | grep . && { warn "pcap files inside repo dir - they are git-ignored; keep them out of GitHub (payloads/credentials)"; }
[[ $FOUND -eq 0 ]] && ok "No secrets/credentials patterns found" || die "Sensitive patterns found above - redact before pushing"
sha256sum $(ls | grep -v SHA256SUMS) > SHA256SUMS && ok "Integrity manifest: evidence/SHA256SUMS"
