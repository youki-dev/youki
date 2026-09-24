# syntax=docker/dockerfile:1.4

ARG KIND_NODE_VERSION=v1.34.0

FROM kindest/node:${KIND_NODE_VERSION} AS kind-base

FROM kind-base AS youki-build
# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libsystemd-dev \
    build-essential \
    libelf-dev \
    libseccomp-dev \
    libclang-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/rustup.sh && sh /tmp/rustup.sh -y --profile=minimal
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /youki
# Copy source code and build with required features
COPY . .
RUN cargo build --release -p youki --features "v1 v2 systemd"

FROM scratch AS shim
COPY --from=youki-build /youki/target/release/youki /

FROM kind-base AS kind-fetch
ARG TARGETARCH
ARG KIND_VERSION=v0.30.0
RUN curl -sSLf https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${TARGETARCH} > /root/kind && chmod +x /root/kind

FROM scratch AS kind-bin
COPY --from=kind-fetch /root/kind /kind

FROM kind-base AS kind-node-base
RUN <<EOF
set -e
echo '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.youki]' >> /etc/containerd/config.toml
echo '  runtime_type = "io.containerd.runc.v2"' >> /etc/containerd/config.toml
echo '   [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.youki.options]' >> /etc/containerd/config.toml
echo '     BinaryName = "/usr/local/bin/youki"' >> /etc/containerd/config.toml
EOF
# Install runtime dependency for youki
RUN apt-get update && apt-get install -y --no-install-recommends libseccomp2 \
    && rm -rf /var/lib/apt/lists/*
COPY --link --from=shim /* /usr/local/bin/

# Default node image: SystemdCgroup disabled for all runtimes (cgroupfs driver)
FROM kind-node-base AS kind-node
RUN sed -i 's,SystemdCgroup = true,,' /etc/containerd/config.toml

# Node image: SystemdCgroup enabled for all runtimes including youki.
# kindest/node has no dbus; this tests the /run/systemd/private fallback in youki.
FROM kind-node-base AS kind-node-systemd-cgroup
RUN echo '     SystemdCgroup = true' >> /etc/containerd/config.toml

# Kind node for CRI-O
FROM kind-base AS kind-node-crio
ARG CRIO_VERSION=v1.34
RUN <<EOF
set -eux
apt-get update
# gnupg dearmors the repository key. skopeo loads the installer image, because
# `kind load docker-image` writes only to containerd. youki needs libseccomp2.
apt-get install -y --no-install-recommends gnupg skopeo libseccomp2
install -d -m 0755 /etc/apt/keyrings
curl -fsSL "https://download.opensuse.org/repositories/isv:/cri-o:/stable:/${CRIO_VERSION}/deb/Release.key" \
    | gpg --batch --yes --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://download.opensuse.org/repositories/isv:/cri-o:/stable:/${CRIO_VERSION}/deb/ /" \
    > /etc/apt/sources.list.d/cri-o.list
apt-get update
# kind has its own /etc/crictl.yaml for containerd. Remove it, or dpkg stops
# at a conffile prompt. The CRI-O version points at the crio socket.
rm -f /etc/crictl.yaml
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cri-o
rm -rf /var/lib/apt/lists/*
# kind has its own CNI (kindnetd), so keep the CRI-O bridge disabled.
# CRI-O uses the systemd cgroup manager by default, which needs sd-bus. A kind
# node has no dbus, and container creation then fails with "cannot open
# sd-bus". Use cgroupfs, like the kind-node target above. The cgroupfs manager
# needs conmon_cgroup "pod".
printf '[crio.runtime]\ncgroup_manager = "cgroupfs"\nconmon_cgroup = "pod"\n' \
    > /etc/crio/crio.conf.d/20-cgroupfs.conf
systemctl disable containerd
systemctl enable crio
EOF
