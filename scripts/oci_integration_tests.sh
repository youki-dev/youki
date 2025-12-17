#!/bin/bash -eu

ROOT=$(git rev-parse --show-toplevel)

RUNTIME=${1:-.}/youki
OCI_TEST_DIR=${ROOT}/tests/oci-runtime-tests/src/github.com/opencontainers/runtime-tools
PATTERN=${2:-.}
cd $OCI_TEST_DIR

test_cases=(
  "create/create.t"
  "default/default.t"
  "delete_only_create_resources/delete_only_create_resources.t"
  "delete_resources/delete_resources.t"
  "hooks_stdin/hooks_stdin.t"
  "kill_no_effect/kill_no_effect.t"
  "killsig/killsig.t"
  "linux_cgroups_devices/linux_cgroups_devices.t"
  # This case includes checking for features that are excluded from linux kernel 5.0, so even runc doesn't pass it.
  # ref. https://github.com/docker/cli/pull/2908
  # "linux_cgroups_relative_blkio/linux_cgroups_relative_blkio.t"
  "linux_cgroups_relative_cpus/linux_cgroups_relative_cpus.t"
  "linux_cgroups_relative_devices/linux_cgroups_relative_devices.t"
  "linux_cgroups_relative_hugetlb/linux_cgroups_relative_hugetlb.t"
  "linux_cgroups_relative_memory/linux_cgroups_relative_memory.t"
  "linux_cgroups_relative_pids/linux_cgroups_relative_pids.t"
  "linux_mount_label/linux_mount_label.t"
  "linux_ns_nopath/linux_ns_nopath.t"
  "linux_ns_path/linux_ns_path.t"
  "linux_ns_path_type/linux_ns_path_type.t"
  # This test case requires that an apparmor profile named 'acme_secure_profile' has been installed on the system. It needs to allow the capabilities
  # validated by runtime-tools otherwise the test case will fail despite the profile being available.
  # "linux_process_apparmor_profile/linux_process_apparmor_profile.t"
  # "misc_props/misc_props.t" runc also fails this, check out https://github.com/youki-dev/youki/pull/1347#issuecomment-1315332775
  "mounts/mounts.t"
  "poststart/poststart.t"
  "poststart_fail/poststart_fail.t"
  "poststop/poststop.t"
  "poststop_fail/poststop_fail.t"
  "prestart/prestart.t"
  "prestart_fail/prestart_fail.t"
  "process_capabilities/process_capabilities.t"
  # Record the tests that runc also fails to pass below, maybe we will fix this by origin integration test, issue: https://github.com/youki-dev/youki/issues/56
  # "start/start.t"
  "state/state.t"

  # The below tests have already been implemented in our integration tests, `contest`.
  # "delete/delete.t"
  # "hooks/hooks.t"
  # "hostname/hostname.t"
  # "kill/kill.t"
  # # This case includes checking for features that are excluded from linux kernel 5.0, so even runc doesn't pass it.
  # # ref. https://github.com/docker/cli/pull/2908
  # # "linux_cgroups_blkio/linux_cgroups_blkio.t"
  # "linux_cgroups_cpus/linux_cgroups_cpus.t"
  # "linux_cgroups_hugetlb/linux_cgroups_hugetlb.t"
  # "linux_cgroups_memory/linux_cgroups_memory.t"
  # "linux_cgroups_network/linux_cgroups_network.t"
  # "linux_cgroups_pids/linux_cgroups_pids.t"
  # "linux_cgroups_relative_network/linux_cgroups_relative_network.t"
  # "linux_devices/linux_devices.t"
  # "linux_masked_paths/linux_masked_paths.t"
  # # This test case hangs on the Github Action. Runtime-tools has an issue filed from 2019 that the clean up step hangs. Otherwise, the test case passes.
  # # Ref: https://github.com/opencontainers/runtime-tools/issues/698
  # # "linux_ns_itype/linux_ns_itype.t"
  # "linux_readonly_paths/linux_readonly_paths.t"
  # "linux_rootfs_propagation/linux_rootfs_propagation.t"
  # "linux_uid_mappings/linux_uid_mappings.t"
  # "linux_seccomp/linux_seccomp.t"
  # "linux_sysctl/linux_sysctl.t"
  # # This test case passed on local box, but not on Github Action. `runc` also fails on Github Action, so likely it is an issue with the test.
  # # "pidfile/pidfile.t"
  # "process/process.t"
  # "process_capabilities_fail/process_capabilities_fail.t"
  # "process_oom_score_adj/process_oom_score_adj.t"
  # "process_rlimits/process_rlimits.t"
  # "process_rlimits_fail/process_rlimits_fail.t"
  # "root_readonly_true/root_readonly_true.t"
  # "process_user/process_user.t"
)

check_environment() {
  test_case=$1
  if [[ $test_case =~ .*(memory|hugetlb).t ]]; then
    if [[ ! -e "/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes" ]]; then
        return 1
    fi
  fi
  if [[ $test_case == "delete_only_create_resources/delete_only_create_resources.t" ]]; then
    if [[ ! -e "/sys/fs/cgroup/pids/cgrouptest/tasks" ]]; then
        return 1
    fi
  fi
}

if [[ ! -e $RUNTIME ]]; then
  if ! which $RUNTIME ; then
    echo "$RUNTIME not found"
    exit 1
  fi
fi

for case in "${test_cases[@]}"; do
  if [[ ! -e "${OCI_TEST_DIR}/validation/$case" ]]; then
    GO111MODULE=auto GOPATH=${ROOT}/tests/oci-runtime-tests make runtimetest validation-executables
    break
  fi
done


for case in "${test_cases[@]}"; do
  if ! check_environment $case; then
    echo "Skip $case because your environment doesn't support this test case"
    continue
  fi

  if [ $PATTERN != "." ] && [[ ! $case =~ $PATTERN ]]; then
    continue
  fi

  echo "Running $case"
  logfile="./log/$case.log"
  mkdir -p "$(dirname $logfile)"
  sudo RUST_BACKTRACE=1 RUNTIME=${RUNTIME} ${OCI_TEST_DIR}/validation/$case >$logfile 2>&1 || (cat $logfile && exit 1)
  if [ 0 -ne $(grep "not ok" $logfile | wc -l ) ]; then
    if [ 0 -eq $(grep "# cgroupv2 is not supported yet " $logfile | wc -l ) ]; then
      echo "Skip $case because oci-runtime-tools doesn't support cgroup v2"
      continue;
    fi
    cat $logfile
    exit 1
  fi
  sleep 1
done
