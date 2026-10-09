#!/usr/bin/env bash
set -euo pipefail

# This is a simple script to stress test `cargo test` to rule out flaky tests.

COUNT=${1:-20}

for i in $(seq 1 "${COUNT}")
do 
    echo "Run test ${i} iteration..."
    cargo test -- --nocapture
done