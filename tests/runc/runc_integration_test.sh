#!/bin/bash -u

RUNTIME=${1:-./youki}
ROOT=$(git rev-parse --show-toplevel)
RUNC_DIR="${ROOT}/tests/runc/src/github.com/opencontainers/runc"
PATTERN_FILE="${ROOT}/${2:-tests/runc/runc_test_pattern}"

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
for name in "${TEST_NAMES[@]}"; do
  if [[ $name =~ ^\[skip\] ]]; then
    echo "skip: $name"
    continue
  fi

  # escape [](){}+?*.,'
  TEST_CASE=$(echo "$name" | sed 's/\\/\\\\/g; s/\[/\\[/g; s/\]/\\]/g; s/(/\\(/g; s/)/\\)/g; s/+/\\+/g; s/?/\\?/g; s/*/\\*/g; s/\./\\./g; s/{/\\{/g; s/}/\\}/g; s/,/\\,/g;')
  echo $TEST_CASE
  sudo -E PATH="$PATH" script -q -e -c "bats  -f \"^$TEST_CASE$\" -t tests/integration"
done
