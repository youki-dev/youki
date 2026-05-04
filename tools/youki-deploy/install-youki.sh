#!/usr/bin/env bash
# Install youki onto a kind node and register it with containerd.
# Designed to run inside a privileged DaemonSet pod that mounts the host's
# /usr/local/bin and /etc/containerd as hostPath volumes, with hostPID enabled.
set -euo pipefail

HOST_BIN_DIR=${HOST_BIN_DIR:-/host/usr/local/bin}
HOST_CONTAINERD_CONFIG=${HOST_CONTAINERD_CONFIG:-/host/etc/containerd/config.toml}
RUNTIME_HANDLER=${RUNTIME_HANDLER:-youki}
MARKER="# youki-deploy:${RUNTIME_HANDLER}"

echo "[youki-deploy] Installing youki on $(hostname)"

install -m 0755 -D /opt/youki/bin/youki "${HOST_BIN_DIR}/youki"

if grep -qF "${MARKER}" "${HOST_CONTAINERD_CONFIG}"; then
    echo "[youki-deploy] containerd already configured, skipping config patch"
else
    echo "[youki-deploy] Patching ${HOST_CONTAINERD_CONFIG}"
    cat >>"${HOST_CONTAINERD_CONFIG}" <<EOF

${MARKER}
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.${RUNTIME_HANDLER}]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.${RUNTIME_HANDLER}.options]
    BinaryName = "${HOST_BIN_DIR#/host}/youki"
    SystemdCgroup = false
EOF
    echo "[youki-deploy] Restarting containerd via host PID 1"
    nsenter -t 1 -m -u -i -n -p -- systemctl restart containerd
fi

echo "[youki-deploy] Done. Sleeping to keep DaemonSet pod Ready."
exec sleep infinity
