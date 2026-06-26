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
RUN cargo build --release -p youki --features "v2 systemd"

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    util-linux \
    && rm -rf /var/lib/apt/lists/*
COPY --from=youki-build /youki/target/release/youki /opt/youki/bin/youki
COPY tools/youki-deploy/install-youki.sh /opt/youki/bin/install-youki.sh
RUN chmod +x /opt/youki/bin/install-youki.sh /opt/youki/bin/youki
ENTRYPOINT ["/opt/youki/bin/install-youki.sh"]
