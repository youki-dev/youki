# youki threat model

This document describes what youki considers a security vulnerability. Read it
before you report an issue as described in [SECURITY.md](SECURITY.md).

## What youki is

youki is a low-level container runtime written in Rust. It implements the
[OCI Runtime Specification](https://github.com/opencontainers/runtime-spec).
Given an OCI runtime configuration (`config.json`) and a root file system, youki
sets up namespaces, cgroups, capabilities, seccomp, devices, mounts, and
AppArmor and SELinux labels. Then it executes the container process. The same
code is available as the `libcontainer` and `libcgroups` crates. youki can also
run WebAssembly workloads through wasmer, wasmedge, and wasmtime.

youki is not a container engine, an image builder, or an orchestrator. A
container engine such as containerd, Docker, or Podman runs youki, as root or as
an unprivileged user (rootless).

## Core principle

youki must enforce the isolation that `config.json` asks for. If youki does what
`config.json` requests, there is no youki vulnerability, even if the
configuration is insecure. A vulnerability exists when untrusted input makes
youki apply weaker isolation than the configuration requests.

youki does not harden or second-guess the configuration. It does enforce a few
checks regardless of the configuration. For example, it allows only a procfs to
be mounted on `/proc`, and only a few files, such as the ones that lxcfs
emulates, to be mounted under it. A way to bypass such a check is a
vulnerability.

Some isolation features depend on build-time Cargo features, such as `seccomp`
and `cgroupsv2_devices`. If `config.json` requests isolation that the build
cannot enforce, youki must fail. A build that silently ignores the requested
isolation has a vulnerability.

## Trust boundaries

| Input | Trust level | Notes |
|-------|-------------|-------|
| `config.json` | Trusted, with exceptions | The container engine provides it and validates user input. This includes hooks. See [Configuration](#configuration). |
| Command line, global options, and environment | Trusted | This includes `--root`, `--log`, `--systemd-cgroup`, `exec --process`, the console socket, and the pid file. |
| Container state directory | Trusted | It is on the host and the container cannot reach it. The default is `/run/youki`. |
| Bundle files other than `config.json` and the rootfs | Trusted | The engine provides them. |
| Callers of the `libcontainer` and `libcgroups` crates | Trusted | |
| Container rootfs contents | Untrusted | Binaries, libraries, symlinks, device nodes, and mount points. This is the main attacker-controlled input. |
| Contents of volumes that the container can write to | Untrusted | Another container can change them while youki sets up a container. |
| Processes in the container | Untrusted | They can race youki during `create`, `run`, and `exec`. |
| What youki sees through the container's `/proc`, `/sys`, `/dev`, and writable cgroup files | Untrusted | The container can replace or shadow them. |

### Configuration

youki does not check `config.json` against any policy. Engines, however, often
fill some of its fields from a user who is not trusted with the host, for
example from an image config or a Kubernetes pod spec. The fields fall into two
groups.

The first group sets the isolation and privileges of the container. An
untrusted user must never control these fields. If an engine allows that, the
bug is in the engine, not in youki.

- Mount sources, types, and options.
- The rootfs path.
- Devices, the cgroup path, and resource limits.
- Capabilities, seccomp, AppArmor and SELinux labels, `noNewPrivileges`, masked
  paths, and read-only paths.
- Namespace paths and user namespace mappings.
- Sysctls.
- Hooks.

The second group describes only what runs inside the container. It has the
process arguments, environment, working directory, uid and gid, hostname, and
mount destinations. Engines often take these fields from untrusted input. If a
value in the second group makes youki break the requested isolation, it is a
youki vulnerability. For example, runc's CVE-2024-21626 was exploited by
setting the working directory to `/proc/self/fd/<N>`, which pointed to a leaked
host directory.

Fields added to the runtime spec in the future belong to the first group unless
this document says otherwise.

## In scope

The attacker controls the rootfs contents, the contents of writable volumes,
the code that runs in the container, and the second group of `config.json`
fields. The following are vulnerabilities:

- Symlink, `..`, bind-mount, or mount-point tricks in the rootfs or a volume
  that make youki read, write, mount, chmod, chown, or create files outside the
  rootfs. This includes TOCTOU races.
- Rootfs contents or container processes that make youki apply a weaker
  security policy than requested. Examples are a dropped seccomp filter, a
  missing capability drop, a skipped masked path, and a wrong LSM label. The
  process that `youki exec` starts must get the same policy as the container.
- Leaks of host file descriptors, mounts, namespaces, or environment into the
  container.
- Races between youki and container processes during `create`, `run`, `exec`,
  `update`, `ps`, and `checkpoint`.
- Container escape through the youki binary, such as overwriting it through
  `/proc/self/exe` (CVE-2019-5736).
- Privilege escalation in rootless mode, such as in the user namespace setup,
  the use of `newuidmap` and `newgidmap`, or cgroup access.
- Memory-safety bugs in youki's `unsafe` code that untrusted input can reach.

## Out of scope

- Anything that needs a crafted value in the first group of `config.json`
  fields. Examples are host path mounts, extra capabilities, disabled seccomp,
  host namespaces, and missing masked paths. Report these to the engine that
  generated the configuration.
- Attacks on youki while it sets up or joins a container that rely on
  capabilities that the configuration grants, such as `CAP_SYS_PTRACE` without
  a user namespace.
- Bugs that need control of the host, the container engine, youki's command
  line or environment, the state directory, or the youki binary.
- Denial of service by a container against itself, and resource use within the
  cgroup limits. A failure to apply limits that `config.json` requests is in
  scope.
- Kernel bugs and weaknesses in namespaces, cgroups, seccomp, LSMs, or
  overlayfs that youki only uses. Report these to the
  [Linux kernel security team](https://www.kernel.org/doc/html/latest/process/security-bugs.html).
- The shared-kernel model of containers. Stronger isolation needs a VM-based
  runtime.
- The content of container images, such as malicious binaries, vulnerable
  libraries, or leaked secrets.
- Bugs in wasmer, wasmedge, wasmtime, CRIU, libseccomp, systemd, or other
  external components, unless youki uses them incorrectly.
- Crashes caused by a trusted caller that passes invalid arguments to
  `libcontainer` or `libcgroups`.
- Findings in tests, CI, documentation, and scripts (`tests/`, `scripts/`,
  `.github/`) that do not affect the shipped youki binary.

## Reporting

Show the proof of concept through a container engine, such as containerd,
Docker, Podman, or Kubernetes. Do not invoke youki directly. When you invoke
youki directly, you control all of `config.json`, so the issue cannot be told
apart from an explicit configuration request. You can run youki directly while
you develop the proof of concept.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Do not open a public issue or pull request.
