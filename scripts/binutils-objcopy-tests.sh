#!/bin/bash
# Run binutils' own objcopy.exp against gobjcopy.
#
# Usage:
#   scripts/binutils-objcopy-tests.sh [full] [--target TRIPLET] [--build-dir DIR]
#
#   (default)     host x86_64, build directory /tmp/bu-build, objcopy.exp only
#   full          the whole binutils testsuite (includes compress.exp)
#   --target      cross target triplet, e.g. aarch64-linux-gnu or
#                 loongarch64-linux-gnu
#   --build-dir   directory configured with --target=TRIPLET and built with
#                 `make all-binutils all-gas all-ld`; defaults to /tmp/bu-build
#                 for the host and /tmp/bu-TRIPLET for a cross target
#
# The script builds the current checkout's gobjcopy, installs it as
# DIR/binutils/objcopy, runs `make check-binutils` in DIR and prints the
# PASS/FAIL counts plus the list of failing tests.  Concurrent runs are
# serialised with flock.
set -u

export PATH=/usr/local/go/bin:$PATH

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK=/tmp/binutils-objcopy-test.lock
# binutils' testsuite calls $TARGET-cc / $TARGET-gcc to build its executable
# fixtures.  Distributions sometimes only install a versioned name (for
# example loongarch64-linux-gnu-gcc-13), so the script can prepend a directory
# of symlinks.
SHIM=/tmp/gobjcopy-cross-toolchain

usage() {
  cat <<'EOF'
Usage: scripts/binutils-objcopy-tests.sh [full] [--target TRIPLET] [--build-dir DIR]

  (default)     host x86_64, build directory /tmp/bu-build, objcopy.exp only
  full          the whole binutils testsuite (includes compress.exp)
  --target      cross target triplet, e.g. aarch64-linux-gnu or
                loongarch64-linux-gnu
  --build-dir   directory configured with --target=TRIPLET and built with
                `make all-binutils all-gas all-ld`
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

FULL=0
TARGET=""
BUILD=""
while [ $# -gt 0 ]; do
  case "$1" in
    full|--full)
      FULL=1
      ;;
    --target)
      [ $# -ge 2 ] || die "--target needs a triplet"
      TARGET=$2
      shift
      ;;
    --target=*)
      TARGET=${1#*=}
      ;;
    --build-dir)
      [ $# -ge 2 ] || die "--build-dir needs a directory"
      BUILD=$2
      shift
      ;;
    --build-dir=*)
      BUILD=${1#*=}
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ -n "$TARGET" ]; then
  BUILD=${BUILD:-/tmp/bu-$TARGET}
  TAG=${TARGET//\//_}
  LOG=/tmp/check-go-$TAG.log
  LABEL=$TARGET
else
  BUILD=${BUILD:-/tmp/bu-build}
  LOG=/tmp/check-go.log
  LABEL="host"
fi

[ -d "$BUILD/binutils" ] || die \
  "build directory $BUILD has no binutils/ subdirectory; configure it with --target=${TARGET:-host} and run 'make all-binutils all-gas all-ld' first"

# find_versioned NAME prints the newest NAME-VERSION executable found on PATH.
# It is only used for cross compilers installed under a versioned name.
find_versioned() {
  local base=$1 best="" dir cand
  local IFS=:
  for dir in $PATH; do
    [ -d "$dir" ] || continue
    cand=$(find "$dir" -maxdepth 1 \( -type f -o -type l \) \
      -name "$base-[0-9]*" -perm -u+x 2>/dev/null | sort -V | tail -n 1)
    if [ -n "$cand" ]; then
      best=$cand
    fi
  done
  printf '%s' "$best"
}

# prepare_cross_cc makes $TARGET-gcc and $TARGET-cc available on PATH when a
# versioned compiler exists.  binutils' top-level Makefile uses -cc for some
# targets (loongarch64) and -gcc for others (aarch64).
prepare_cross_cc() {
  local triple=$1 name src made=0
  mkdir -p "$SHIM/$triple"
  for name in "$triple-gcc" "$triple-cc"; do
    if command -v "$name" >/dev/null 2>&1; then
      continue
    fi
    src=$(find_versioned "$name")
    if [ -z "$src" ]; then
      # -cc is rarely installed; fall back to the matching gcc, plain or
      # versioned, and give it the name the testsuite expects.
      src=$(command -v "$triple-gcc" 2>/dev/null || true)
    fi
    if [ -z "$src" ]; then
      src=$(find_versioned "$triple-gcc")
    fi
    if [ -z "$src" ]; then
      echo "warning: $name not found; executable test cases may be UNTESTED" >&2
      continue
    fi
    ln -sf "$src" "$SHIM/$triple/$name"
    echo "using $src for $name"
    made=1
  done
  if [ "$made" -eq 1 ]; then
    PATH="$SHIM/$triple:$PATH"
    export PATH
  fi
}

if [ -n "$TARGET" ]; then
  prepare_cross_cc "$TARGET"
fi

# Serialise builds too: two concurrent invocations would otherwise race on
# writing $ROOT/gobjcopy.
exec 9>"$LOCK"
flock 9

cd "$ROOT" || die "cannot cd to $ROOT"
built=0
for attempt in 1 2 3; do
  if go build -o gobjcopy ./cmd/gobjcopy; then
    built=1
    break
  fi
  echo "build attempt $attempt failed; retrying" >&2
  sleep 2
done
[ "$built" -eq 1 ] || die "cannot build gobjcopy"

cp gobjcopy "$BUILD/binutils/objcopy"
touch "$BUILD/binutils/objcopy"

if [ "$FULL" -eq 1 ]; then
  ( cd "$BUILD" && make check-binutils ) >"$LOG" 2>&1 || true
else
  ( cd "$BUILD" && make check-binutils RUNTESTFLAGS="objcopy.exp" ) >"$LOG" 2>&1 || true
fi

count() {
  awk -v key="$1" '
    index($0, "# of " key) == 1 { n = $NF; found = 1 }
    END { if (found) print n; else print 0 }
  ' "$LOG"
}

if ! grep -q '^# of expected passes' "$LOG"; then
  echo "error: testsuite produced no summary; last lines of $LOG:" >&2
  tail -n 20 "$LOG" >&2
  exit 1
fi

passes=$(count "expected passes")
fails=$(count "unexpected failures")
unsupported=$(count "unsupported tests")
untested=$(count "untested testcases")
xpass=$(count "unexpected successes")
xfail=$(count "expected failures")
unresolved=$(count "unresolved testcases")

mapfile -t failures < <(grep -E '^FAIL:' "$LOG" | sed 's/^FAIL: //' | sort -u)

echo "target:      $LABEL"
echo "build dir:   $BUILD"
echo "log:         $LOG"
printf 'PASS:        %s\n' "$passes"
printf 'FAIL:        %s\n' "$fails"
printf 'unsupported: %s\n' "$unsupported"
printf 'untested:    %s\n' "$untested"
[ "$xpass" -ne 0 ] && printf 'XPASS:       %s\n' "$xpass"
[ "$xfail" -ne 0 ] && printf 'XFAIL:       %s\n' "$xfail"
[ "$unresolved" -ne 0 ] && printf 'UNRESOLVED:  %s\n' "$unresolved"
echo "failures:    ${#failures[@]}"
for f in "${failures[@]}"; do
  echo "  - $f"
done

if [ "$fails" -ne 0 ] || [ "$unresolved" -ne 0 ]; then
  exit 1
fi
