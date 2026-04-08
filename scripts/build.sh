#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
HOST_TARGET=$(rustc -Vv | grep ^host: | cut -d' ' -f2)

usage_exit() {
    echo "Usage: $0 [-r] [-o dir] [-c crate] [-f features] [-t target] [-x]" 1>&2
    exit 1
}

VERSION=debug
CRATE="youki"
TARGET=${TARGET:-$HOST_TARGET}
CARGO=${CARGO:-}
features=""

while getopts f:ro:c:t:xh OPT; do
    case $OPT in
        f) features=${OPTARG}
            ;;
        o) output=${OPTARG}
            ;;
        r) VERSION=release
            ;;
        c) CRATE=${OPTARG}
            ;;
        t) TARGET=${OPTARG}
            ;;
        x) CARGO=cross
            ;;
        h) usage_exit
            ;;
        \?) usage_exit
            ;;
    esac
done

shift $((OPTIND - 1))

OPTION=""
if [ "${VERSION}" = release ]; then
    OPTION="--release"
fi

# expand target shortcuts
case "$TARGET" in
    musl)
        TARGET="$(uname -m)-unknown-linux-musl"
        ;;
    gnu|glibc)
        TARGET="$(uname -m)-unknown-linux-gnu"
        ;;
    arm64|aarch64)
        TARGET="aarch64-unknown-linux-musl"
        ;;
    amd64|x86_64)
        TARGET="x86_64-unknown-linux-musl"
        ;;
    ppc64le)
        TARGET="powerpc64le-unknown-linux-gnu"
        ;;
esac

FEATURES=()
if [ -n "${features}" ]; then
    FEATURES=("--features=${features}")
fi
echo "* FEATURES: ${features:-<default>}"
echo "* TARGET: ${TARGET}"

OUTPUT=${output:-$ROOT/bin}
mkdir -p "$OUTPUT"

CARGO_SH="$(dirname "$0")/cargo.sh"
export CARGO_BUILD_TARGET="$TARGET"

if [ "$CRATE" == "youki" ]; then
    rm -f "${OUTPUT}/youki"
    "$CARGO_SH" build ${OPTION} "${FEATURES[@]}" --bin youki
    mv "$("$CARGO_SH" --print-target-dir)/${TARGET}/${VERSION}/youki" "${OUTPUT}/"
fi

if [ "$CRATE" == "contest" ]; then
    find ${OUTPUT} -maxdepth 1 -type f -name "contest" -exec rm -ifv {} \;
    "$CARGO_SH" build ${OPTION} "${FEATURES[@]}" --bin contest
    mv ${ROOT}/target/${TARGET}/${VERSION}/contest ${OUTPUT}/

    find ${OUTPUT} -maxdepth 1 -type f -name "runtimetest" -exec rm -ifv {} \;
    CONTEST_TARGET="$ROOT/contest-target"
    CARGO_TARGET_DIR=${CONTEST_TARGET} RUSTFLAGS="-Ctarget-feature=+crt-static" "$CARGO_SH" build ${OPTION} "${FEATURES[@]}" --bin runtimetest
    mv ${CONTEST_TARGET}/${TARGET}/${VERSION}/runtimetest ${OUTPUT}/
fi
