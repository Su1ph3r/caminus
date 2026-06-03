#!/usr/bin/env bash
# Runs poutine over every corpus case and records the rule IDs it reports, as
# benchmark/results-poutine.jsonl (one {"id":..,"rules":[..]} per line).
#
# poutine analyzes a git repo, so each case is copied to a temp repo and
# committed first. Must run on Linux (poutine's local analyzer does not load
# repos under Windows go-git). Usage:
#
#   POUTINE=/path/to/poutine bash benchmark/compare_poutine.sh
set -euo pipefail
cd "$(dirname "$0")"
POUTINE="${POUTINE:-poutine}"
OUT=results-poutine.jsonl
: > "$OUT"

for dir in corpus/*/; do
  id=$(basename "$dir")
  W=$(mktemp -d)
  cp -r "$dir." "$W"/
  (
    cd "$W"
    git init -q
    git add -A
    git -c user.email=t@t -c user.name=t commit -qm fixture
  )
  json=$("$POUTINE" analyze_local "$W" -f json --quiet --disable-version-check 2>/dev/null || echo '{}')
  rules=$(printf '%s' "$json" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    d={}
rs=sorted({ (f.get("rule_id") or f.get("rule") or "") for f in d.get("findings",[]) } - {""})
print(json.dumps(rs))')
  printf '{"id":"%s","rules":%s}\n' "$id" "$rules" >> "$OUT"
  rm -rf "$W"
done

echo "wrote $OUT ($(wc -l < "$OUT") cases)"
