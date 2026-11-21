#!/bin/bash
set -euo pipefail

RUNTIME=${1:-./youki}
ROOT=$(git rev-parse --show-toplevel)
RUNC_DIR="${ROOT}/tests/runc/src/github.com/opencontainers/runc"
PATTERN_FILE="${ROOT}/${2:-tests/runc/runc_test_pattern}"
TEST_TIMEOUT=${RUNC_TEST_TIMEOUT:-60s}

# The value is passed through script's shell command, so accept durations only.
if [[ ! $TEST_TIMEOUT =~ ^[0-9]+([.][0-9]+)?[smhd]?$ ]] ||
  [[ ! $TEST_TIMEOUT =~ [1-9] ]]; then
  echo "error: RUNC_TEST_TIMEOUT must be a positive timeout duration" >&2
  exit 1
fi

if [[ ! -f "$RUNC_DIR/Makefile" ]]; then
  echo "error: Makefile not found under: $RUNC_DIR" >&2
  echo "please run: git submodule update --init --recursive" >&2
  exit 1
fi

if [[ ! -x "$RUNTIME" ]]; then
  echo "$RUNTIME binary not found"
  exit 1
fi
cp "$RUNTIME" "$RUNC_DIR/runc"
chmod +x "$RUNC_DIR/runc"

cd "$RUNC_DIR"

sudo make test-binaries

readarray -t TEST_NAMES < "$PATTERN_FILE"
failed=0
for name in "${TEST_NAMES[@]}"; do
  if [[ $name =~ ^\[skip\] ]]; then
    echo "skip: $name"
    continue
  fi

  # escape [](){}+?*.,'
  TEST_CASE=$(echo "$name" | sed 's/\\/\\\\/g; s/\[/\\[/g; s/\]/\\]/g; s/(/\\(/g; s/)/\\)/g; s/+/\\+/g; s/?/\\?/g; s/*/\\*/g; s/\./\\./g; s/{/\\{/g; s/}/\\}/g; s/,/\\,/g;')
  echo "$TEST_CASE"
  # Run timeout inside the PTY so it can terminate bats and its process group,
  # including helpers holding the console socket open. Escalate if TERM hangs.
  if sudo -E PATH="$PATH" script -q -e -c "timeout --kill-after=10s $TEST_TIMEOUT bats -f \"^$TEST_CASE$\" -t tests/integration"; then
    continue
  else
    status=$?
    echo "FAIL: $name (exit status $status)" >&2
    failed=$((failed + 1))
  fi
done

echo "Failed tests: $failed"
if (( failed > 0 )); then
  exit 1
fi
