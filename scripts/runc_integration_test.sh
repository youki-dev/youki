#!/bin/bash -u

RUNTIME=${1:-youki}

ROOT=$(git rev-parse --show-toplevel)
RUNC_DIR="${ROOT}/tests/runc/src/github.com/opencontainers/runc"
RUNC_TEST_DIR="${ROOT}/tests/runc/src/github.com/opencontainers/runc/tests/integration"

if [[ "$RUNTIME" == "youki" ]]; then
  if [[ ! -x ./youki ]]; then
    echo "youki binary not found"
    exit 1
  fi
  cp ./youki "$RUNC_DIR/runc"
  chmod +x "$RUNC_DIR/runc"
fi

cd "$RUNC_DIR"

# Skipping this test because it hangs and stops responding.
SKIP_PATTERN=$(cat <<EOF
cgroups.bats:runc run/create should refuse pre-existing frozen cgroup
run.bats:runc run [execve error]
events.bats:events oom
events.bats:events --stats with psi data
events.bats:events --interval default
rlimits.bats:runc run with RLIMIT_NOFILE(The same as system's hard value)
mounts.bats:runc run [tmpcopyup]
mounts.bats:runc run [/proc is a symlink]
mounts.bats:runc run [ro /sys/fs/cgroup mounts + cgroupns]
mounts.bats:runc run [mount order, container bind-mount source]
mounts.bats:runc run [mount order, container bind-mount source] (userns)
mounts.bats:runc run [mount order, container idmap source]
mounts.bats:runc run [mount order, container idmap source] (userns)
env.bats:env var HOME is set only once
idmap.bats:simple idmap mount [userns]
EOF
)

while IFS= read -r line; do
  [[ -z "$line" ]] && continue

  file_part="${line%%:*}"
  test_pattern="${line#*:}"

  file_path=$(find "$RUNC_TEST_DIR" -name "$file_part")
  if [[ -z "$file_path" || ! -f "$file_path" ]]; then
    echo "Warning: file $file_part not found"
    continue
  fi

  escaped_pattern=$(printf '%s\n' "$test_pattern" | sed 's/[^^]/[&]/g; s/\^/\\^/g')
  sed -i "/$escaped_pattern/a skip \"skip runc integration test in youki\"" "$file_path"
done <<< "$SKIP_PATTERN"

sudo make test-binaries
# Build runc binary only if runtime is 'runc'
if [[ "$RUNTIME" == "runc" ]]; then
  sudo make runc
fi
sudo -E PATH="$PATH" script -q -e -c 'bats -t  tests/integration'

# cleanup
find "$RUNC_TEST_DIR" -name "*.bats" -exec sed -i '/skip "skip runc integration test in youki"/d' {} +
