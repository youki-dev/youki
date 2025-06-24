#!/bin/bash -u

RUNTIME=${1:-./youki}
ROOT=$(git rev-parse --show-toplevel)
RUNC_DIR="${ROOT}/tests/runc/src/github.com/opencontainers/runc"
RUNC_TEST_DIR="${ROOT}/tests/runc/src/github.com/opencontainers/runc/tests/integration"

if [[ ! -x "$RUNTIME" ]]; then
  echo "$RUNTIME binary not found"
  exit 1
fi
cp $RUNTIME "$RUNC_DIR/runc"
chmod +x "$RUNC_DIR/runc"

cd "$RUNC_DIR"

# Skipping this test because it hangs and stops responding.
SKIP_PATTERN=$(cat <<EOF
capabilities.bats:runc run no capability
capabilities.bats:runc run with unknown capability
capabilities.bats:runc run with new privileges
capabilities.bats:runc run with some capabilities
capabilities.bats:runc exec --cap
capabilities.bats:runc exec --cap [ambient is set from spec]
capabilities.bats:runc run [ambient caps not set in inheritable result in a warning]
cgroups.bats:runc create (limits + cgrouppath + permission on the cgroup dir) succeeds
cgroups.bats:runc exec (cgroup v2 + init process in non-root cgroup) succeeds
cgroups.bats:runc run (blkio weight)
cgroups.bats:runc run (per-device multiple iops via unified)
cgroups.bats:runc run (hugetlb limits)
cgroups.bats:runc run (cgroup v2 resources.unified only)
cgroups.bats:runc run (cgroup v2 resources.unified swap)
cgroups.bats:runc run (cgroupv2 mount inside container)
cgroups.bats:runc exec should refuse a paused container
cgroups.bats:runc exec --ignore-paused
cgroups.bats:runc run/create should error for a non-empty cgroup
cgroups.bats:runc run/create should refuse pre-existing frozen cgroup
cpu_affinity.bats:runc exec [CPU affinity, only initial set from process.json]
cpu_affinity.bats:runc exec [CPU affinity, initial and final set from process.json]
cpu_affinity.bats:runc exec [CPU affinity, initial and final set from config.json]
create.bats:runc create exec
debug.bats:global --debug
debug.bats:global --debug to --log
debug.bats:global --debug to --log --log-format 'text'
debug.bats:global --debug to --log --log-format 'json'
delete.bats:@test "runc delete"
delete.bats:delete --force in cgroupv2 with subcgroups
dev.bats:runc run [redundant default /dev/tty]
dev.bats:runc run/update [device cgroup deny]
dev.bats:runc run [device cgroup allow rw char device]
dev.bats:runc run [device cgroup allow rm block device]
env.bats:empty HOME env var is overridden
env.bats:empty HOME env var is overridden with multiple overrides
env.bats:env var HOME is set only once
env.bats:env var with new-line is honored
events.bats:events oom
events.bats:events --interval 1s
events.bats:events --interval 100ms
events.bats:events --stats with psi data
events.bats:events --interval default
events.bats:events --stats
exec.bats:runc exec [exit codes]
exec.bats:runc exec ls -la
exec.bats:runc exec --user
exec.bats:runc exec --additional-gids
exec.bats:runc exec --preserve-fds
exec.bats:runc --debug exec
exec.bats:runc --debug --log exec
exec.bats:runc exec --cgroup subcgroup [v2]
exec.bats:runc exec [execve error]
exec.bats:runc exec check default home
help.bats:runc -h
help.bats:runc command -h
help.bats:runc foo -h
hooks.bats:runc create [second createRuntime hook fails]
hooks.bats:runc create [hook fails]
hooks.bats:runc run [hook fails]
hooks.bats:runc run [startContainer hook should inherit process environment]
hooks_so.bats:runc run (hooks library tests)
idmap.bats:simple idmap mount [userns]
idmap.bats:simple idmap mount [no userns]
idmap.bats:write to an idmap mount [userns]
idmap.bats:write to an idmap mount [no userns]
idmap.bats:idmap mount with propagation flag [userns]
idmap.bats:idmap mount with relative path [userns]
idmap.bats:idmap mount with bind mount [userns]
idmap.bats:idmap mount with bind mount [no userns]
idmap.bats:two idmap mounts (same mapping) with two bind mounts [userns]
idmap.bats:same idmap mount (different mappings) [userns]
idmap.bats:same idmap mount (different mappings) [no userns]
idmap.bats:multiple idmap mounts (different mappings) [userns]
idmap.bats:multiple idmap mounts (different mappings) [no userns]
idmap.bats:idmap mount (complicated mapping) [userns]
idmap.bats:idmap mount (complicated mapping) [no userns]
idmap.bats:idmap mount (non-recursive idmap) [userns]
idmap.bats:idmap mount (non-recursive idmap) [no userns]
idmap.bats:idmap mount (idmap flag) [userns]
idmap.bats:idmap mount (idmap flag) [no userns]
idmap.bats:idmap mount (ridmap flag) [userns]
idmap.bats:idmap mount (ridmap flag) [no userns]
idmap.bats:idmap mount (idmap flag, implied mapping) [userns]
idmap.bats:idmap mount (ridmap flag, implied mapping) [userns]
idmap.bats:idmap mount (idmap flag, implied mapping, userns join) [userns]
ioprio.bats:ioprio_set is applied to process group
kill.bats:kill detached busybox
kill.bats:kill KILL [host pidns]
kill.bats:kill KILL [host pidns + init gone]
list.bats:list
mask.bats:mask paths [file]
mask.bats:mask paths [directory]
mask.bats:mask paths [prohibit symlink /proc]
mask.bats:mask paths [prohibit symlink /sys]
mounts.bats:runc run [tmpcopyup]
mounts.bats:runc run [/proc is a symlink]
mounts.bats:runc run [ro /sys/fs/cgroup mounts + cgroupns]
mounts.bats:runc run [mount order, container bind-mount source]
mounts.bats:runc run [mount order, container bind-mount source] (userns)
mounts.bats:runc run [mount order, container idmap source]
mounts.bats:runc run [mount order, container idmap source] (userns)
mounts.bats:runc run [ro /dev mount]
mounts_recursive.bats:runc run [rbind,ro mount is read-only but not recursively]
mounts_sshfs.bats:runc run [mount(8)-unlike behaviour: --bind with clearing flag]
mounts_sshfs.bats:runc run [implied-rw bind mount of a ro fuse sshfs mount]
mounts_sshfs.bats:runc run [explicit-rw bind mount of a ro fuse sshfs mount]
mounts_sshfs.bats:runc run [dev,exec,suid,atime bind mount of a nodev,nosuid,noexec,noatime fuse sshfs mount]
mounts_sshfs.bats:runc run [ro bind mount of a nodev,nosuid,noexec fuse sshfs mount]
mounts_sshfs.bats:runc run [ro,symfollow bind mount of a rw,nodev,nosymfollow fuse sshfs mount]
mounts_sshfs.bats:runc run [ro,noexec bind mount of a nosuid,noatime fuse sshfs mount]
mounts_sshfs.bats:runc run [bind mount {no,rel,strict}atime semantics]
personality.bats:runc run personality for i686
personality.bats:runc run personality with exec for i686
personality.bats:runc run personality with exec for x86_64
pidfd-socket.bats:runc create [ --pidfd-socket ]
pidfd-socket.bats:runc run [ --pidfd-socket ]
pidfd-socket.bats:runc exec [ --pidfd-socket ] [cgroups_v2]
ps.bats:ps -e -x
rlimits.bats:runc run with RLIMIT_NOFILE(The same as system's hard value)
rlimits.bats:runc exec with RLIMIT_NOFILE(The same as system's hard value)
rlimits.bats:runc exec with RLIMIT_NOFILE(Bigger than system's hard value)
rlimits.bats:runc exec with RLIMIT_NOFILE(Smaller than system's hard value)
run.bats:runc run --keep
run.bats:runc run --keep (check cgroup exists)
run.bats:runc run with tmpfs
run.bats:runc run with tmpfs perms
run.bats:runc run [/proc/self/exe clone]
run.bats:runc run [joining existing container namespaces]
run.bats:runc run [execve error]
scheduler.bats:scheduler is applied
scheduler.bats:scheduler vs cpus
seccomp-notify.bats:runc run [seccomp] (SCMP_ACT_NOTIFY noNewPrivileges false)
seccomp-notify.bats:runc exec [seccomp] (SCMP_ACT_NOTIFY noNewPrivileges false)
seccomp-notify.bats:runc exec [seccomp] (SCMP_ACT_NOTIFY noNewPrivileges true)
seccomp-notify.bats:runc run [seccomp] (SCMP_ACT_NOTIFY important syscalls noNewPrivileges false)
seccomp-notify.bats:runc run [seccomp] (SCMP_ACT_NOTIFY kill seccompagent)
seccomp-notify.bats:runc run [seccomp] (SCMP_ACT_NOTIFY no seccompagent)
seccomp-notify.bats:runc run [seccomp] (SCMP_ACT_NOTIFY error chmod)
seccomp.bats:runc run [seccomp -ENOSYS handling]
seccomp.bats:runc run [seccomp] (SCMP_ACT_ERRNO default)
seccomp.bats:runc run [seccomp] (SCMP_ACT_ERRNO explicit errno)
seccomp.bats:runc run [seccomp] (SECCOMP_FILTER_FLAG_*)
seccomp.bats:runc run [seccomp] (startContainer hook)
start_hello.bats:runc run as user with no exec bit but CAP_DAC_OVERRIDE set
timens.bats:runc run [timens with no offsets]
timens.bats:runc run [simple timens]
timens.bats:runc exec [simple timens]
timens.bats:runc run [simple timens + userns]
tty.bats:runc run [stdin not a tty]
tty.bats:runc run [tty ptsname]
tty.bats:runc run [tty owner]
tty.bats:runc run [tty owner] ({u,g}id != 0)
tty.bats:runc exec [stdin not a tty]
tty.bats:runc exec [tty ptsname]
tty.bats:runc exec [tty owner]
tty.bats:runc exec [tty owner] ({u,g}id != 0)
tty.bats:runc exec [tty consolesize]
umask.bats:umask
update.bats:update cgroup v1/v2 common limits
update.bats:update cgroup cpu limits
update.bats:cpu burst
update.bats:set cpu period with no quota (invalid period)
update.bats:update cpu period with no previous period/quota set
update.bats:update cpu quota with no previous period/quota set
update.bats:update cgroup cpu.idle
update.bats:update memory vs CheckBeforeUpdate
userns.bats:userns with 2 inaccessible mounts
userns.bats:userns with inaccessible mount + exec
userns.bats:userns join other container userns
userns.bats:userns join other container userns [bind-mounted nsfd]
userns.bats:userns join external namespaces [wrong userns owner]
version.bats:runc version
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
sudo -E PATH="$PATH" script -q -e -c 'bats -t  tests/integration'

# cleanup
find "$RUNC_TEST_DIR" -name "*.bats" -exec sed -i '/skip "skip runc integration test in youki"/d' {} +
