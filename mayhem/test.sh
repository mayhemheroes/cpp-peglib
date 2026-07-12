#!/usr/bin/env bash
#
# mayhem/test.sh — RUN cpp-peglib's own googletest suite (built by mayhem/build.sh
# into build-tests/test/peglib-test-main). Runs only; never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/build-tests/test/peglib-test-main"
if [ ! -x "$RUNNER" ]; then
  echo "FATAL: $RUNNER missing — mayhem/build.sh must build the test suite" >&2
  emit_ctrf "googletest" 0 1 0
  exit 1
fi

OUT="$("$RUNNER" 2>&1)"
STATUS=$?
echo "$OUT" | tail -20

TOTAL=$(echo "$OUT" | sed -n 's/^\[==========\] \([0-9]\+\) tests\? from .* ran.*/\1/p' | tail -1)
PASSED=$(echo "$OUT" | sed -n 's/^\[  PASSED  \] \([0-9]\+\) tests\?.*/\1/p' | tail -1)
SKIPPED=$(echo "$OUT" | sed -n 's/^\[  SKIPPED \] \([0-9]\+\) tests\?.*/\1/p' | tail -1)
TOTAL=${TOTAL:-0}; PASSED=${PASSED:-0}; SKIPPED=${SKIPPED:-0}
FAILED=$(( TOTAL - PASSED - SKIPPED ))
# A crashed/aborted runner can under-report: treat nonzero exit with no counted failures as a failure.
if [ "$STATUS" -ne 0 ] && [ "$FAILED" -le 0 ]; then FAILED=1; fi
if [ "$TOTAL" -eq 0 ]; then FAILED=$(( FAILED > 0 ? FAILED : 1 )); fi

emit_ctrf "googletest" "$PASSED" "$FAILED" "$SKIPPED"
