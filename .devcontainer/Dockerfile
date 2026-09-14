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

# Configure Docker to use youki as the default runtime.
# Docker invokes the wrapper at /usr/local/bin/youki which forwards to /workspaces/youki/youki.
COPY <<'EOF' /etc/docker/daemon.json
{
  "default-runtime": "youki",
  "runtimes": {
    "youki": {
      "path": "/usr/local/bin/youki",
      "runtimeArgs": ["--debug"]
    }
  }
}
EOF

# Wrapper script that forces logs to /var/log/youki.log.
# containerd-shim-runc-v2 passes `--log` and `--log-format` by default, so this wrapper strips those args and keeps the fixed log path.
COPY <<'EOF' /usr/local/bin/youki
#!/bin/bash
args=("--log=/var/log/youki.log")
while [ $# -gt 0 ]; do
  case "$1" in
    --log=* | --log-format=*) shift ;;
    --log | --log-format) shift; [ $# -gt 0 ] && shift ;;
    *) args+=("$1"); shift ;;
  esac
done
/workspaces/youki/youki "${args[@]}"
EOF

RUN chmod +x /usr/local/bin/youki
