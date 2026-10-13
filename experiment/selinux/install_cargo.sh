#!/bin/bash

set -eux

LOG_FILE="/tmp/user_provision.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

export PATH="$HOME/.cargo/bin:$PATH"

if command -v cargo >/dev/null 2>&1; then
    echo "Rust/Cargo is already installed."
else
    echo "Installing Rust/Cargo via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        echo "Cargo still not available after rustup install. Exiting."
        exit 1
    fi
    echo "Rust/Cargo installed successfully."
fi
cargo --version

echo "Ensuring $HOME/.cargo/env is sourced in .bashrc for future logins..."
if ! grep -q 'source "$HOME/.cargo/env"' "$HOME/.bashrc" 2>/dev/null; then
    echo 'source "$HOME/.cargo/env"' >> "$HOME/.bashrc"
fi
