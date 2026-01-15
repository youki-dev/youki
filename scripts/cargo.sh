#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   CARGO_BUILD_TARGET=<target> cargo.sh <args>...
#
# This script wraps `cargo` invocations, and calls either `cargo`
# or `cross`, as appropriate. It checks the value of the
# `CARGO_BUILD_TARGET` environment variable, and calls `cargo` if
# the target matches the host target, and `cross` otherwise.
#
# Use of `cargo`/`cross` can be forced by setting the `CARGO`
# environment variable to `cargo`/`cross`. This is useful for
# instance to force the use of `cross` in CI even for the host
# target.
#
# When cross is used, the target directory will be appended
# `cross-<target>` to avoid libc conflicts in host binaries (e.g.,
# build scripts, proc macros). The computed value of the target
# directory can be obtained with `cargo.sh --print-target-dir`.
#
# Lastly, when using `cross` this scrips sets some configuration
# to allow running `youki` tests inside the `cross`` container.
# Please check the comments in this scrips to learm more about that.
#
# Limitations:
#  * You **must** use the `CARGO_BUILD_TARGET` environment variable
#    to specify the build target instead of using the `--target` CLI
#    argument, or a configuration file like `.cargo/config.toml`.
#  * If **must** use the `CARGO_TARGET_DIR` environment variable to
#    specify the target directory instead of using the `--target-dir`
#    CLI argument, or a configuration file like `.cargo/config.toml`.
#

ROOT=$(git rev-parse --show-toplevel)
HOST_TARGET=$(rustc -Vv | grep ^host: | cut -d' ' -f2)

export CARGO_BUILD_TARGET="${CARGO_BUILD_TARGET:-$HOST_TARGET}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

if [ "$CARGO_BUILD_TARGET" == "$HOST_TARGET" ]; then
    CARGO="${CARGO:-cargo}"
else
    CARGO="${CARGO:-cross}"
fi

if [ "$1" == "fmt" ]; then
    # running cargo fmt fails when run through cross
    # also cargo fmt is platform independent
    CARGO="cargo"

    # Use nightly for `cargo fmt` as `rustfmt.toml` uses unstable features.
    set -- "+nightly" "$@"
fi

if [ "$CARGO" == "cross" ]; then
    export CROSS_BUILD_OPTS="--quiet"
    export CARGO_TARGET_DIR="$CARGO_TARGET_DIR/cross-$CARGO_BUILD_TARGET"

    # mount run to have access to dbus socket.
    # mount /tmp so as shared for test_make_parent_mount_private
    # Then there are few "hacks" specificallt for test_task_addition
    # run with user same as the invoking user, so that the dbus is connected with correct user
    # we want pid ns of host, because we will be connecting to the host dbus, and it needs task pid from host
    # finally we need to mount the cgroup as read-only, as we need that to check if the tasks are correctly added
    # Note: Mount `-v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro` to read the information of the created test user.
    export CROSS_CONTAINER_OPTS="--privileged --user `id -u`:`id -g` --pid=host -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro -v /run:/run --mount=type=bind,source=/tmp,destination=/tmp,bind-propagation=shared"
fi

if [ "$1" == "--print-target-dir" ]; then
    echo "$CARGO_TARGET_DIR"
    exit 0
fi

"$CARGO" "$@"
