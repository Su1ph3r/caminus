#!/usr/bin/env bash
# Runs octoscan (Synacktiv, actionlint-based) over every GitHub corpus case and
# records the finding "kind" values it reports, as results-octoscan.jsonl.
#
# octoscan analyzes individual workflow files (its directory walk expects a
# different layout), so each case's .github/workflows/*.yml are scanned directly
# and the kinds aggregated. octoscan is GitHub-only; GitLab cases are recorded
# with "platform":"gitlab" so the scorer marks them N/A rather than missed.
#
# Usage:  OCTOSCAN=/path/to/octoscan bash benchmark/compare_octoscan.sh
set -euo pipefail
cd "$(dirname "$0")"
OCTOSCAN="${OCTOSCAN:-octoscan}"
OUT=results-octoscan.jsonl
: > "$OUT"

for dir in corpus/*/; do
  id=$(basename "$dir")
  if [ -f "$dir/.gitlab-ci.yml" ]; then
    printf '{"id":"%s","platform":"gitlab","rules":[]}\n' "$id" >> "$OUT"
    continue
  fi
  kinds=""
  for f in "$dir".github/workflows/*.yml; do
    [ -e "$f" ] || continue
    # octoscan exits non-zero when it reports findings; capture its output first
    # so pipefail does not discard a successful-but-flagged scan.
    out=$("$OCTOSCAN" scan "$f" --format json 2>/dev/null || true)
    k=$(printf '%s' "$out" | python -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: d=[]
print(" ".join(x.get("kind","") for x in d))')
    kinds="$kinds $k"
  done
  rules=$(printf '%s' "$kinds" | python -c 'import sys,json; print(json.dumps(sorted({w for w in sys.stdin.read().split() if w})))')
  printf '{"id":"%s","platform":"github","rules":%s}\n' "$id" "$rules" >> "$OUT"
done

echo "wrote $OUT ($(wc -l < "$OUT") cases)"
