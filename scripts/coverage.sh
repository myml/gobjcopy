#!/bin/bash
# Report statement coverage for the whole module (-coverpkg=./...).
# Usage: scripts/coverage.sh [profile]
set -e
export PATH=/usr/local/go/bin:$PATH
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROFILE=${1:-/tmp/gobjcopy-cover.out}
cd "$ROOT"
go test ./... -coverpkg=./... -coverprofile="$PROFILE" -count=1 > /tmp/gobjcopy-cover.log 2>&1 || {
	cat /tmp/gobjcopy-cover.log
	exit 1
}
python3 - "$PROFILE" <<'PY'
import collections, sys
path = sys.argv[1]
blocks = {}
for line in open(path):
    line = line.strip()
    if not line or line.startswith("mode:"):
        continue
    loc, n, count = line.rsplit(" ", 2)
    f, rest = loc.split(":", 1)
    start, end = rest.split(",")
    key = (f, start, end)
    st, c = int(n), int(count)
    if key in blocks:
        of, os_, oc = blocks[key]
        blocks[key] = (of, os_, max(oc, c))
    else:
        blocks[key] = (f, st, c)
tot = collections.Counter()
cov = collections.Counter()
for f, st, c in blocks.values():
    tot[f] += st
    if c > 0:
        cov[f] += st
rows = sorted(tot, key=lambda f: cov[f] / tot[f])
print(f"{'file':52s} {'stmts':>6s} {'cov':>7s}")
for f in rows:
    name = f.replace("github.com/gobjcopy/gobjcopy/", "")
    print(f"{name:52s} {tot[f]:6d} {cov[f] / tot[f] * 100:6.1f}%")
alln, allc = sum(tot.values()), sum(cov.values())
print("-" * 68)
print(f"TOTAL {allc}/{alln} statements = {allc / alln * 100:.1f}%")
PY
