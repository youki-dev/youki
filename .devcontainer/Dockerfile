ARG VARIANT="bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/rust:1-${VARIANT}

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN <<'EOF'
apt-get update

# For building
apt-get install -y --no-install-recommends \
  build-essential git libclang-dev libelf-dev libseccomp-dev libssl-dev libsystemd-dev pkg-config

# For debugging
apt-get install -y --no-install-recommends \
  podman bpftrace

rm -rf /var/lib/apt/lists/*

curl --proto '=https' --tlsv1.2 -sSf "https://just.systems/install.sh" | bash -s -- --to /usr/bin

curl -L -o /usr/bin/kubectl "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x /usr/bin/kubectl

VERSION="$(curl -sSfL "https://api.github.com/repos/rust-lang/mdBook/releases/latest" | jq -r .tag_name)"
curl -sSfL "https://github.com/rust-lang/mdBook/releases/download/$VERSION/mdbook-$VERSION-$(uname -m)-unknown-linux-musl.tar.gz" | tar -xzvC /usr/bin/ mdbook

# Install the Rust nightly toolchain because `cargo fmt` relies on unstable rustfmt settings.
curl -sSf "https://sh.rustup.rs" | sh -s -- -y
rustup install nightly
rustup component add rustfmt
rustup component add clippy

# Systemd is not available in this Dev Container, but Podman `event_logger` defaults to journald.
# Switch the logger to file so container startup does not fail.
sed -i 's/^# events_logger = "journald"/events_logger = "file"/' /usr/share/containers/containers.conf
EOF

# Install docker with youki
COPY <<'EOF' /etc/docker/daemon.json
  {
    "runtimes": {
      "youki": {
        "path": "/workspaces/youki/youki"
      }
    }
  }
EOF
