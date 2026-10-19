#!/bin/bash
# Run binutils' own objcopy.exp against gobjcopy.
# Usage: scripts/binutils-objcopy-tests.sh [full]
#   (default) only objcopy.exp, the acceptance suite for this project
#   full      the whole binutils testsuite (includes compress.exp etc.)
set -e
export PATH=/usr/local/go/bin:$PATH
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=/tmp/bu-build
cd "$ROOT"
go build -o gobjcopy ./cmd/gobjcopy
exec 9>/tmp/binutils-objcopy-test.lock
flock 9
cp gobjcopy "$BUILD/binutils/objcopy"
touch "$BUILD/binutils/objcopy"
cd "$BUILD"
if [ "$1" = "full" ]; then
  make check-binutils > /tmp/check-go.log 2>&1 || true
else
  make check-binutils RUNTESTFLAGS="objcopy.exp" > /tmp/check-go.log 2>&1 || true
fi
grep -E '^# of' /tmp/check-go.log || true
grep -E '^FAIL' /tmp/check-go.log | sed 's/^FAIL: //' | sort > /tmp/fails.txt || true
echo "failures: $(wc -l < /tmp/fails.txt)"
