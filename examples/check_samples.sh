#!/usr/bin/env bash
# Call POST /pcap/dns-response-check for every bundled sample capture.
# Usage:  examples/check_samples.sh [host:port]   (default localhost:8000)
set -euo pipefail

BASE="${1:-http://localhost:8000}"
BASE="${BASE%/}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pcap"

# sample file -> "query_frame cutoff_frame"
declare -A FRAMES=(
  [01-complete-unfragmented.pcap]="1 2"
  [02-complete-fragments-out-of-order.pcap]="1 5"
  [03-missing-fragment.pcap]="1 3"
  [04-only-non-first-fragments.pcap]="1 3"
  [05-conflicting-first-fragments.pcap]="1 5"
  [06-no-response.pcap]="1 3"
  [07-question-mismatch.pcap]="1 3"
  [08-nxdomain.pcap]="1 2"
)

for name in $(printf '%s\n' "${!FRAMES[@]}" | sort); do
  read -r query_frame cutoff_frame <<<"${FRAMES[$name]}"
  echo "=== ${name} (query=${query_frame}, cutoff=${cutoff_frame})"
  curl -sS -X POST "${BASE}/pcap/dns-response-check" \
    -F "file=@${DIR}/${name}" \
    -F "query_frame=${query_frame}" \
    -F "cutoff_frame=${cutoff_frame}" | python3 -m json.tool --no-ensure-ascii
  echo
done
