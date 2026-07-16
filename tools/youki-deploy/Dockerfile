# syntax=docker/dockerfile:1.4

FROM rust:1-slim-bookworm AS youki-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libsystemd-dev \
    build-essential \
    libelf-dev \
    libseccomp-dev \
    libclang-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /youki
COPY . .
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/youki/target \
    cargo build --release -p youki --features "v2 systemd" && \
    cp target/release/youki /tmp/youki

FROM debian:bookworm-slim
ARG TARGETARCH
ARG KUBECTL_VERSION=v1.34.9
RUN apt-get update && apt-get install -y --no-install-recommends \
    util-linux \
    && rm -rf /var/lib/apt/lists/*
# kubectl is used by install-youki.sh to label the node as runtime-ready.
ADD --chmod=0755 https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl /usr/local/bin/kubectl
COPY --from=youki-build /tmp/youki /opt/youki/bin/youki
COPY tools/youki-deploy/install-youki.sh /opt/youki/bin/install-youki.sh
RUN chmod +x /opt/youki/bin/install-youki.sh /opt/youki/bin/youki
ENTRYPOINT ["/opt/youki/bin/install-youki.sh"]
