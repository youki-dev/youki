#!/usr/bin/env bash

# Usage
#   features_test.sh
# Environment variables
#   VERBOSE=1: show output from test functions
# Return
#   0: Passed
#   1: Failed

set -uo pipefail

CARGO_SH="$(dirname "$0")/cargo.sh"
: "${VERBOSE:=0}"

# Test Harness
PASS=0
SKIP=0
FAIL=0
FAILED_TESTS=()
SKIPPED_TESTS=()
SKIP_CODE=77

run_test() {
    local cmdline="$*"
    local output

    output=$( "$@" 2>&1 )
    case $? in
        0)
            PASS=$((PASS + 1))
            printf '[ PASS ] %s\n' "$cmdline" ;;
        "$SKIP_CODE")
	    SKIP=$((SKIP + 1))
            SKIPPED_TESTS+=("$cmdline")
            printf '[ SKIP ] %s\n' "$cmdline" ;;
        *)
            FAIL=$((FAIL + 1))
	    FAILED_TESTS+=("$cmdline")
            printf '[ FAIL ] %s\n' "$cmdline" ;;
    esac

    if [[ -n "$output" && "$VERBOSE" == "1" ]]; then
        printf '%s\n' "$output" | sed 's/^/    | /'
    fi
}

test_package_features() {
    echo "building $1 with features $2"
    "$CARGO_SH" build --no-default-features --package "$1" --features "$2"
}

test_features() {
    echo "testing features $1"
    "$CARGO_SH" build --no-default-features --features "$1"
    if (( $? != 0 )); then
        echo "test skipped due to build error"
        return $SKIP_CODE
    fi
    "$CARGO_SH" test run --no-default-features --features "$1" -- --test-threads=1
}

main() {
    run_test test_package_features "libcontainer" "v1"
    run_test test_package_features "libcontainer" "v2"
    run_test test_package_features "libcontainer" "systemd"
    run_test test_package_features "libcontainer" "v2 cgroupsv2_devices"
    run_test test_package_features "libcontainer" "systemd cgroupsv2_devices"
    run_test test_package_features "libcontainer" "v1 libseccomp"
    run_test test_package_features "libcontainer" "v2 libseccomp"
    run_test test_package_features "libcontainer" "systemd libseccomp"
    run_test test_package_features "libcontainer" "v2 cgroupsv2_devices libseccomp"
    run_test test_package_features "libcontainer" "systemd cgroupsv2_devices libseccomp"

    run_test test_package_features "libcgroups" "v1"
    run_test test_package_features "libcgroups" "v2"
    run_test test_package_features "libcgroups" "systemd"
    run_test test_package_features "libcgroups" "v2 cgroupsv2_devices"
    run_test test_package_features "libcgroups" "systemd cgroupsv2_devices"

    run_test test_features "v1"
    run_test test_features "v2"
    run_test test_features "systemd"
    run_test test_features "v2 cgroupsv2_devices"
    run_test test_features "systemd cgroupsv2_devices"
    run_test test_features "v1 seccomp"
    run_test test_features "v2 seccomp"
    run_test test_features "systemd seccomp"
    run_test test_features "v2 cgroupsv2_devices seccomp"
    run_test test_features "systemd cgroupsv2_devices seccomp"

    local total=$((PASS + FAIL + SKIP))
    echo
    echo "=============================="
    printf 'Total: %d  Passed: %d  Failed: %d Skipped: %d\n' "$total" "$PASS" "$FAIL" "$SKIP"
    if (( VERBOSE )); then
        if (( FAIL > 0 )); then
            echo "Failed tests:"
            printf '  - %s\n' "${FAILED_TESTS[@]}"
        fi
        if (( SKIP > 0 )); then
            echo "Skipped tests:"
            printf '  - %s\n' "${SKIPPED_TESTS[@]}"
        fi
    fi
    echo "=============================="

    (( FAIL + SKIP == 0 ))
}

main "$@"
