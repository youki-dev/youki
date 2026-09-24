#!/usr/bin/env bash
# Install youki on a Kubernetes node and add it to containerd or CRI-O.
#
# Run this in a privileged DaemonSet pod with hostPID. Mount /usr/local/bin
# and the config directory of the runtime: /etc/containerd or /etc/crio.
set -euo pipefail

HOST_BIN_DIR=${HOST_BIN_DIR:-/host/usr/local/bin}
REAL_BIN_DIR=${REAL_BIN_DIR:-/usr/local/bin}
HOST_CONTAINERD_CONFIG=${HOST_CONTAINERD_CONFIG:-/host/etc/containerd/config.toml}
HOST_CRIO_CONFIG_DIR=${HOST_CRIO_CONFIG_DIR:-/host/etc/crio/crio.conf.d}
CRIO_DROPIN_NAME=${CRIO_DROPIN_NAME:-99-youki.conf}
CRIO_MONITOR_PATH=${CRIO_MONITOR_PATH:-}
# containerd, crio, or auto.
CRI_RUNTIME=${CRI_RUNTIME:-auto}
RUNTIME_HANDLER=${RUNTIME_HANDLER:-youki}
NODE_READY_LABEL=${NODE_READY_LABEL:-youki.dev/runtime-ready}
MARKER="# youki-deploy:${RUNTIME_HANDLER}"

# Run a command on the host, through PID 1.
host_run() {
    nsenter -t 1 -m -u -i -n -p -- "$@"
}

# Find the runtime of the node. Used only when CRI_RUNTIME is auto.
detect_cri_runtime() {
    if host_run systemctl is-active --quiet crio 2>/dev/null; then
        echo crio
    elif host_run systemctl is-active --quiet containerd 2>/dev/null; then
        echo containerd
    elif [ -d "${HOST_CRIO_CONFIG_DIR}" ]; then
        echo crio
    elif [ -f "${HOST_CONTAINERD_CONFIG}" ]; then
        echo containerd
    else
        return 1
    fi
}

# Find conmon on the host. CRI-O needs its path, and each distribution uses a
# different one. The deb and rpm packages install it outside of PATH.
detect_crio_monitor_path() {
    local candidate
    for candidate in /usr/libexec/crio/conmon /usr/libexec/podman/conmon /usr/bin/conmon; do
        if host_run sh -c "test -x '${candidate}'" 2>/dev/null; then
            echo "${candidate}"
            return
        fi
    done
}

configure_containerd() {
    if [ ! -f "${HOST_CONTAINERD_CONFIG}" ]; then
        echo "[youki-deploy] ${HOST_CONTAINERD_CONFIG} not found." \
             "Is the host's /etc/containerd mounted into this pod?" >&2
        exit 1
    fi

    if grep -qF "${MARKER}" "${HOST_CONTAINERD_CONFIG}"; then
        echo "[youki-deploy] containerd already configured, skipping config patch"
        return
    fi

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
    host_run systemctl restart containerd
}

configure_crio() {
    # CRI-O reads crio.conf.d in alphabetical order, so a drop-in file adds
    # youki and does not change crio.conf.
    if [ ! -d "$(dirname "${HOST_CRIO_CONFIG_DIR}")" ]; then
        echo "[youki-deploy] $(dirname "${HOST_CRIO_CONFIG_DIR}") not found." \
             "Is the host's /etc/crio mounted into this pod?" >&2
        exit 1
    fi
    mkdir -p "${HOST_CRIO_CONFIG_DIR}"

    local dropin="${HOST_CRIO_CONFIG_DIR}/${CRIO_DROPIN_NAME}"
    if [ -f "${dropin}" ] && grep -qF "${MARKER}" "${dropin}"; then
        echo "[youki-deploy] CRI-O already configured, skipping config patch"
        return
    fi

    echo "[youki-deploy] Writing ${dropin}"
    # Do not set cgroup_manager. It applies to the node, not to one runtime,
    # so youki uses the manager of CRI-O.
    cat >"${dropin}" <<EOF
${MARKER}
[crio.runtime.runtimes.${RUNTIME_HANDLER}]
runtime_path = "${REAL_BIN_DIR}/youki"
runtime_type = "oci"
runtime_root = "/run/youki"
EOF

    if [ -z "${CRIO_MONITOR_PATH}" ]; then
        CRIO_MONITOR_PATH=$(detect_crio_monitor_path)
    fi
    if [ -n "${CRIO_MONITOR_PATH}" ]; then
        echo "monitor_path = \"${CRIO_MONITOR_PATH}\"" >>"${dropin}"
    else
        echo "[youki-deploy] conmon not found in the usual locations, leaving" \
             "monitor_path unset for CRI-O to resolve" >&2
    fi

    # Correct the SELinux label. A file copied through a bind mount can get
    # the wrong one, and SELinux then stops CRI-O from starting youki.
    # restorecon does nothing if SELinux is off, and some hosts do not have it.
    host_run restorecon -F "${REAL_BIN_DIR}/youki" 2>/dev/null \
        || echo "[youki-deploy] restorecon unavailable or failed, skipping relabel"

    echo "[youki-deploy] Restarting crio via host PID 1"
    host_run systemctl restart crio
}

echo "[youki-deploy] Installing youki on $(hostname)"

install -m 0755 -D /opt/youki/bin/youki "${HOST_BIN_DIR}/youki"

if [ "${CRI_RUNTIME}" = "auto" ]; then
    if ! CRI_RUNTIME=$(detect_cri_runtime); then
        echo "[youki-deploy] Could not detect the CRI runtime on this node." \
             "Set CRI_RUNTIME to 'containerd' or 'crio'." >&2
        exit 1
    fi
    echo "[youki-deploy] Detected CRI runtime: ${CRI_RUNTIME}"
fi

case "${CRI_RUNTIME}" in
    containerd) configure_containerd ;;
    crio) configure_crio ;;
    *)
        echo "[youki-deploy] Unsupported CRI_RUNTIME '${CRI_RUNTIME}'," \
             "expected 'containerd', 'crio' or 'auto'." >&2
        exit 1
        ;;
esac

# Label the node for the youki RuntimeClass. The scheduler starts a pod with
# runtimeClassName youki only on a labelled node, so none starts here before
# the installation is complete.
: "${NODE_NAME:?NODE_NAME must be set (injected via the downward API)}"
echo "[youki-deploy] Labeling node ${NODE_NAME} with ${NODE_READY_LABEL}=true"
kubectl label node "${NODE_NAME}" "${NODE_READY_LABEL}=true" --overwrite

echo "[youki-deploy] Done. Sleeping to keep DaemonSet pod Ready."
exec sleep infinity
