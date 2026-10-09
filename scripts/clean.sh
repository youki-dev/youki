#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)

for bin in youki integration_test runtimetest test.log; do
    if [ -f $bin ]; then
        rm -f "${1}"/$bin
    fi
done

rm -rf "$ROOT"/target "$ROOT"/runtimetest-target

exit 0 # unconditionally return zero
