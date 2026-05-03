#!/bin/bash
#
# Lima environment setup script for SELinux development with Fedora
# This script creates and starts a Lima VM for SELinux development

set -eu -o pipefail

SCRIPT_NAME=$(basename "$0")
TEMP_DIR=""

CPUS=2
MEMORY="2GiB"
VM_NAME="youki-selinux"
FORCE_RECREATE=0
CLEANUP=0
NON_INTERACTIVE=true

# Logging functions
log_info() {
  echo -e "\033[0;32m[INFO]\033[0m $*"
}

log_warn() {
  echo -e "\033[0;33m[WARN]\033[0m $*" >&2
}

log_error() {
  echo -e "\033[0;31m[ERROR]\033[0m $*" >&2
}

# Cleanup function
cleanup() {
  local exit_code=$?
  if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
    log_info "Cleaning up temporary directory ${TEMP_DIR}..."
    rm -rf "${TEMP_DIR}"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

# Display usage information
usage() {
  cat <<USAGE_EOF
Usage: ${SCRIPT_NAME} [options]

Options:
  -h, --help          Show this help message
  -c, --cpus NUMBER   Set CPU cores (default: ${CPUS})
  -m, --memory SIZE   Set memory size (default: ${MEMORY})
  -n, --name NAME     Set VM name (default: ${VM_NAME})
  -f, --force         Force recreate VM if it exists
  -i, --interactive   Enable interactive mode (default: non-interactive)
  --cleanup           Stop and remove the VM
USAGE_EOF
  exit "${1:-0}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage 0
      ;;
    -c|--cpus)
      if [[ -z "$2" || "$2" =~ ^- ]]; then log_error "--cpus requires a number"; usage 1; fi
      CPUS="$2"
      shift 2
      ;;
    -m|--memory)
      if [[ -z "$2" || "$2" =~ ^- ]]; then log_error "--memory requires a size (e.g. 2GiB)"; usage 1; fi
      MEMORY="$2"
      shift 2
      ;;
    -n|--name)
      if [[ -z "$2" || "$2" =~ ^- ]]; then log_error "--name requires a value"; usage 1; fi
      VM_NAME="$2"
      shift 2
      ;;
    -f|--force)
      FORCE_RECREATE=1
      shift
      ;;
    -i|--interactive)
      NON_INTERACTIVE=false
      shift
      ;;
    --cleanup)
      CLEANUP=1
      shift
      ;;
    *)
      log_error "Unknown option: $1"
      usage 1
      ;;
  esac
done

if [[ $CLEANUP -eq 1 ]]; then
  log_info "=== Cleaning up Youki SELinux (Fedora) Development Environment ==="
  if limactl list --json | grep -q "\"name\":\"$VM_NAME\""; then
    log_info "Stopping and removing VM '$VM_NAME'..."
    limactl stop "$VM_NAME" --force || true
    limactl delete --force "$VM_NAME"
    log_info "VM '$VM_NAME' has been removed."
  else
    log_warn "VM '$VM_NAME' does not exist."
  fi
  exit 0
fi

log_info "=== Youki SELinux (Fedora) Development Environment Setup ==="
log_info "Setting up Lima VM for SELinux development with Fedora..."
log_info "Configuration:"
log_info "  - CPUs:   $CPUS"
log_info "  - Memory: $MEMORY"
log_info "  - Name:   $VM_NAME"
log_info "  - Mode:   $([ "$NON_INTERACTIVE" = true ] && echo "non-interactive" || echo "interactive")"
if [[ $FORCE_RECREATE -eq 1 ]]; then
  log_info "  - Force Recreate: yes"
fi

CURRENT_SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
YOUKI_ROOT_DIR=$(cd "$CURRENT_SCRIPT_DIR/../.." && pwd)
log_info "Youki root directory: $YOUKI_ROOT_DIR"
log_info "Script directory: $CURRENT_SCRIPT_DIR"

TEMP_DIR=$(mktemp -d)
if [[ ! -d "${TEMP_DIR}" ]]; then
  log_error "Failed to create temporary directory"
  exit 1
fi

log_info "Generating Lima configuration for Fedora ($TEMP_DIR/lima-fedora.yaml)..."
cat > "$TEMP_DIR/lima-fedora.yaml" << 'LIMA_YAML'
# Lima configuration for SELinux development environment with Fedora

# Using official Fedora Cloud Base Images.
# Replace with a specific version if needed, check https://getfedora.org/en/cloud/download/
# Using Fedora 43 URLs
images:
- location: https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2
  arch: x86_64
  digest: sha256:846574c8a97cd2d8dc1f231062d73107cc85cbbbda56335e264a46e3a6c8ab2f
- location: https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/aarch64/images/Fedora-Cloud-Base-Generic-43-1.6.aarch64.qcow2
  arch: aarch64
  digest: sha256:66031aea9ec61e6d0d5bba12b9454e80ca94e8a79c913d37ded4c60311705b8b

cpus: __CPUS__
memory: "__MEMORY__"

mounts:
  - location: "__YOUKI_ROOT_DIR__"
    mountPoint: "/workdir/youki"
    writable: true
  - location: "~"
    writable: true
  - location: "__CURRENT_SCRIPT_DIR__" # Mount the directory containing the script
    mountPoint: "/tmp/provision_scripts" # Mount to a directory in VM
    writable: false

hostResolver:
  hosts:
    host.lima.internal: host.lima.internal

provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux
      # Execute the mounted system provisioning script
      SCRIPT_PATH="/tmp/provision_scripts/provision_system.sh"
      if [ -f "${SCRIPT_PATH}" ]; then
        echo "Executing ${SCRIPT_PATH}..."
        bash "${SCRIPT_PATH}"
        echo "Finished executing ${SCRIPT_PATH}."
      else
        echo "ERROR - ${SCRIPT_PATH} not found!"
        exit 1
      fi
  - mode: user
    script: |
      #!/bin/bash
      set -eux
      USER_LOG_FILE="/tmp/user_provision.log"
      exec > >(tee -a "${USER_LOG_FILE}") 2>&1 # Log to file and console
      export PATH="$HOME/.cargo/bin:$PATH"

      if ! command -v cargo &> /dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable
        if [ -f "$HOME/.cargo/env" ]; then
            source "$HOME/.cargo/env"
        fi
        if ! command -v cargo &> /dev/null; then
            echo "Cargo still not available after rustup install. Exiting."
            exit 1
        fi
        echo "Rust/Cargo installed successfully."
        cargo --version
      else
        echo "Rust/Cargo is already installed."
        cargo --version
        if [ -f "$HOME/.cargo/env" ]; then # Ensure sourced for current script if already present
             source "$HOME/.cargo/env"
        fi
      fi

      echo "Ensuring $HOME/.cargo/env is sourced in .bashrc for future logins..."
      if ! grep -q 'source "$HOME/.cargo/env"' "$HOME/.bashrc"; then
        echo 'source "$HOME/.cargo/env"' >> "$HOME/.bashrc"
      fi
LIMA_YAML

SED_EXPR=""
SED_EXPR+="s|__CPUS__|${CPUS}|g; "
SED_EXPR+="s|__MEMORY__|${MEMORY}|g; "
SED_EXPR+="s|__YOUKI_ROOT_DIR__|${YOUKI_ROOT_DIR}|g; "
SED_EXPR+="s|__CURRENT_SCRIPT_DIR__|${CURRENT_SCRIPT_DIR}|g; "

sed -i.bak "${SED_EXPR}" "$TEMP_DIR/lima-fedora.yaml"

# Check if the instance already exists
if limactl list --json | grep -q "\"name\":\"$VM_NAME\""; then
  if [[ $FORCE_RECREATE -eq 1 ]]; then
    log_info "VM '$VM_NAME' already exists. Stopping and removing..."
    limactl stop "$VM_NAME" --force || true
    limactl delete --force "$VM_NAME"
  else
    log_info "VM '$VM_NAME' already exists. Starting if not running..."
    if ! limactl list --json | grep -q "\"name\":\"$VM_NAME\",\"status\":\"Running\""; then
      limactl start "$VM_NAME"
    fi
    log_info "SELinux (Fedora) dev environment ready: limactl shell $VM_NAME"
    exit 0
  fi
fi

log_info "Creating and starting Lima VM '$VM_NAME'..."
declare -a CREATE_ARGS=("--name=$VM_NAME")
if [ "$NON_INTERACTIVE" = true ]; then
  CREATE_ARGS+=("--tty=false")
fi

log_info "Running: limactl create ${CREATE_ARGS[*]} \"$TEMP_DIR/lima-fedora.yaml\""
if ! limactl create "${CREATE_ARGS[@]}" "$TEMP_DIR/lima-fedora.yaml"; then
  log_error "Failed to create Lima VM definition. Check logs."
  # Even if create partially succeeded, try starting might reveal logs or state.
  # But for robustness, let's exit if create fails clearly.
  exit 1
fi

# Ensure the VM is started after creation
log_info "Ensuring VM '$VM_NAME' is running..."
if ! limactl start "$VM_NAME"; then
    log_error "Failed to start Lima VM '$VM_NAME' after creation. Check logs with 'limactl logs $VM_NAME' or serial logs."
    # It might be running despite the error, but build/test might fail. Exit for clarity.
    exit 1
fi

log_info "SELinux (Fedora) development environment '$VM_NAME' is ready!"
