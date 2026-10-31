#!/bin/bash
# Check rootless youki when it can not create the container cgroup.
#
# youki then runs the container in its parent cgroup, unless the container is
# in the host PID namespace. "kill --all" and "delete --force" must still stop
# such a container.
#
# usage: no-cgroup.sh <youki>
# Needs unprivileged user namespaces and a static busybox ($BUSYBOX).

set -eu

if [ "${1:-}" != --inner ]; then
    # Run as root in a user and mount namespace, as rootless podman runs the
    # runtime, with a read-only /sys/fs/cgroup.
    exec unshare -rm "$BASH" "$0" --inner "$(realpath "$1")"
fi

youki_bin=$2
busybox=${BUSYBOX:-$(command -v busybox)}
work=$(mktemp -d)
root=$work/state
pids=()

mount --bind /sys/fs/cgroup /sys/fs/cgroup
mount -o remount,bind,ro /sys/fs/cgroup

# A PID namespace to join, owned by our user namespace.
unshare -p --fork --kill-child sleep infinity </dev/null >/dev/null 2>&1 &
holder=$!

cleanup() {
    kill -KILL "$holder" "${pids[@]}" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

youki() {
    "$youki_bin" --root "$root" --log-level warn "$@"
}

alive() {
    local stat
    stat=$(ps -o stat= -p "$1") && [[ $stat != Z* ]]
}

wait_dead() {
    local pid
    for pid; do
        for _ in $(seq 50); do
            alive "$pid" || continue 2
            sleep 0.1
        done
        return 1
    done
}

# bundle <name> <private|host|joined>
bundle() {
    local dir=$work/$1 ns='[{"type":"mount"},{"type":"ipc"},{"type":"uts"}]'
    local proc='{"destination":"/proc","type":"proc","source":"proc"}'
    mkdir -p "$dir"/rootfs/{bin,dev,proc,sys}
    cp "$busybox" "$dir/rootfs/bin/busybox"
    case $2 in
    private) ns=$(jq -c '. + [{"type":"pid"}]' <<<"$ns") ;;
    joined) ns=$(jq -c --arg p "$joined" '. + [{"type":"pid","path":$p}]' <<<"$ns") ;;
    esac
    if [ "$2" != private ]; then
        # A new procfs can not be mounted without a PID namespace of our own.
        proc='{"destination":"/proc","type":"none","source":"/proc","options":["rbind","nosuid","nodev","noexec"]}'
    fi
    jq -n --argjson ns "$ns" --argjson proc "$proc" '{
        ociVersion: "1.0.2",
        process: {
            terminal: false,
            user: {uid: 0, gid: 0},
            args: ["/bin/busybox", "sh", "-c", "/bin/busybox sleep 1000 & exec /bin/busybox sleep 1001"],
            env: ["PATH=/bin"],
            cwd: "/",
            noNewPrivileges: true
        },
        root: {path: "rootfs"},
        mounts: [
            $proc,
            {destination: "/dev", type: "tmpfs", source: "tmpfs", options: ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {destination: "/sys", type: "none", source: "/sys", options: ["rbind", "nosuid", "noexec", "nodev", "ro"]}
        ],
        linux: {namespaces: $ns}
    }' >"$dir/config.json"
}

# start <name> <private|host|joined>: run a container, and set $init and $child.
start() {
    bundle "$1" "$2"
    # A detached container keeps the stdio of youki, so do not use a pipe.
    youki run -d -b "$work/$1" "$1" </dev/null >"$work/$1.log" 2>&1 ||
        fail "$1: run: $(cat "$work/$1.log")"
    init=$(youki state "$1" | jq .pid)
    pids+=("$init")
    child=
    for _ in $(seq 50); do
        child=$(pgrep -P "$init") && break
        sleep 0.1
    done
    [ -n "$child" ] || fail "$1: no child of init $init"
    pids+=("$child")
    [ "$(cat "/proc/$init/cgroup")" = "$(cat /proc/self/cgroup)" ] ||
        fail "$1: youki created a cgroup, the test is invalid"
}

listed() {
    youki list | grep -qw "$1"
}

ns_init=
for _ in $(seq 50); do
    ns_init=$(pgrep -P "$holder") && break
    sleep 0.1
done
[ -n "$ns_init" ] || fail "no PID namespace to join"
joined=/proc/$ns_init/ns/pid

start private-kill private
youki kill --all private-kill KILL || fail "private-kill: kill --all"
wait_dead "$init" "$child" || fail "private-kill: processes survived kill --all"
youki delete private-kill || fail "private-kill: delete"
echo "ok: private PID namespace, kill --all"

start private-delete private
youki delete --force private-delete || fail "private-delete: delete --force"
wait_dead "$init" "$child" || fail "private-delete: processes survived delete --force"
! listed private-delete || fail "private-delete: still listed"
echo "ok: private PID namespace, delete --force"

bundle host host
if youki run -d -b "$work/host" host </dev/null >"$work/host.log" 2>&1; then
    init=$(youki state host | jq .pid)
    sleep 0.5
    # shellcheck disable=SC2207 # pids are words
    pids+=("$init" $(pgrep -P "$init"))
    fail "host: a container in the host PID namespace ran without a cgroup"
fi
! listed host || fail "host: still listed"
echo "ok: host PID namespace, refused"

start joined joined
youki kill --all joined KILL || fail "joined: kill --all"
wait_dead "$init" || fail "joined: init survived kill --all"
youki delete --force joined || fail "joined: delete --force"
! listed joined || fail "joined: still listed"
# The other processes die with the init of the joined namespace.
kill -KILL "$ns_init"
wait_dead "$child" || fail "joined: child survived the joined namespace"
echo "ok: joined PID namespace, kill --all"
