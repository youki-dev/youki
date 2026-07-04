#!/usr/bin/env bash
# This is a temporary test-collection for validating youki runs correctly with podman in rootless mode
# This will be moved to a proper rust based test crate, similar to rust-integration tests soon

set -ex

runtime=$1

podman rm --force --ignore create-test # remove if existing

podman create --runtime $runtime --name create-test hello-world
log=$(podman start -a create-test)
echo $log | grep "This message shows that your installation appears to be working correctly"
podman rm --force --ignore create-test

rand=$(head -c 10 /dev/random | base64)

log=$(podman run --runtime $runtime fedora echo "$rand")
echo $log | grep $rand

podman kill exec-test || true # ignore failure for killing
podman rm --force --ignore exec-test
podman run -d --runtime $runtime --name exec-test busybox sleep 10m

rand=$(head -c 10 /dev/random | base64)

log=$(podman exec --runtime $runtime exec-test echo "$rand")
echo $log | grep $rand

CGROUP_SUB_PATH=$(podman inspect exec-test | jq .[0].State.CgroupPath | tr -d "\"")
CGROUP_PATH="/sys/fs/cgroup$CGROUP_SUB_PATH/cgroup.procs"

# assert we have exactly one process in the cgroup
test "$(cat "$CGROUP_PATH" | wc -l)" -eq 1
# assert pid match
test "$(cat "$CGROUP_PATH")" -eq "$(podman inspect exec-test | jq .[0].State.Pid)"

podman exec -d --runtime $runtime exec-test sleep 5m

# we cannot exactly check the pid of tenant here, instead just check that there are
# two processes in the same cgroup now
test "$(cat "$CGROUP_PATH" | wc -l)" -eq 2

podman kill exec-test
podman rm --force --ignore exec-test
