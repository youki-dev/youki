#!/usr/bin/env bash
# Install youki onto a kind node and register it with containerd.
# Designed to run inside a privileged DaemonSet pod that mounts the host's
# /usr/local/bin and /etc/containerd as hostPath volumes, with hostPID enabled.
set -euo pipefail

HOST_BIN_DIR=${HOST_BIN_DIR:-/host/usr/local/bin}
REAL_BIN_DIR=${REAL_BIN_DIR:-/usr/local/bin}
HOST_CONTAINERD_CONFIG=${HOST_CONTAINERD_CONFIG:-/host/etc/containerd/config.toml}
RUNTIME_HANDLER=${RUNTIME_HANDLER:-youki}
NODE_READY_LABEL=${NODE_READY_LABEL:-youki.dev/runtime-ready}
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
    BinaryName = "${REAL_BIN_DIR}/youki"
    SystemdCgroup = false
EOF
    echo "[youki-deploy] Restarting containerd via host PID 1"
    nsenter -t 1 -m -u -i -n -p -- systemctl restart containerd
fi

# Mark this node as ready for the youki RuntimeClass. Pods with
# runtimeClassName: youki are only scheduled onto nodes with this label,
# which prevents them from landing here before the installation above.
: "${NODE_NAME:?NODE_NAME must be set (injected via the downward API)}"
echo "[youki-deploy] Labeling node ${NODE_NAME} with ${NODE_READY_LABEL}=true"
kubectl label node "${NODE_NAME}" "${NODE_READY_LABEL}=true" --overwrite

echo "[youki-deploy] Done. Sleeping to keep DaemonSet pod Ready."
exec sleep infinity
