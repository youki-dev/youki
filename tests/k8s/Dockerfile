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
RUN cargo build --release -p youki --features "v1 v2"

FROM scratch AS shim
COPY --from=youki-build /youki/target/release/youki /

FROM kind-base AS kind-fetch
ARG TARGETARCH
ARG KIND_VERSION=v0.30.0
RUN curl -sSLf https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${TARGETARCH} > /root/kind && chmod +x /root/kind

FROM scratch AS kind-bin
COPY --from=kind-fetch /root/kind /kind

FROM kind-base
RUN <<EOF
set -e
echo '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.youki]' >> /etc/containerd/config.toml
echo '  runtime_type = "io.containerd.runc.v2"' >> /etc/containerd/config.toml
echo '   [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.youki.options]' >> /etc/containerd/config.toml
echo '     BinaryName = "/usr/local/bin/youki"' >> /etc/containerd/config.toml
sed -i 's,SystemdCgroup = true,,' /etc/containerd/config.toml
EOF
# Install runtime dependency for youki
RUN apt-get update && apt-get install -y --no-install-recommends libseccomp2 \
    && rm -rf /var/lib/apt/lists/*
COPY --link --from=shim /* /usr/local/bin/

