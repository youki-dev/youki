#!/bin/bash

set -eux

LOG_FILE="/tmp/system_provision.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

CRITICAL_DEV_PACKAGES="gcc gcc-c++ make libselinux-devel audit pkgconfig git"

echo "Ensuring critical development packages are installed: $CRITICAL_DEV_PACKAGES..."
for pkg in $CRITICAL_DEV_PACKAGES; do
    installed_by_rpm=false
    if rpm -q "$pkg" >/dev/null 2>&1; then
        installed_by_rpm=true
    fi

    command_exists=false
    is_executable_pkg=false
    cmd_to_check=$pkg

    if [[ "$pkg" == "gcc" || "$pkg" == "gcc-c++" || "$pkg" == "make" || "$pkg" == "git" ]]; then
        is_executable_pkg=true
        if [[ "$pkg" == "gcc-c++" ]]; then cmd_to_check="g++"; fi
    fi
    # pkgconfig provides pkg-config command
    if [[ "$pkg" == "pkgconfig" ]]; then
        is_executable_pkg=true
        cmd_to_check="pkg-config"
    fi

    if $is_executable_pkg; then
        if command -v "$cmd_to_check" >/dev/null 2>&1; then
            command_exists=true
        fi
    elif $installed_by_rpm; then # For non-executable devel libraries, rpm -q is enough
        command_exists=true 
    fi

    if $installed_by_rpm && $command_exists; then
        echo "Package $pkg (command: $cmd_to_check) - OK (already installed or verified)."
    else
        echo "Package $pkg (command: $cmd_to_check) - NOT FOUND or verification failed. Attempting dnf install..."
        if dnf install -y "$pkg"; then
            echo "dnf install -y $pkg SUCCEEDED."
            if $is_executable_pkg; then
                if ! command -v "$cmd_to_check" >/dev/null 2>&1; then
                    echo "CRITICAL - $cmd_to_check (for $pkg) still NOT FOUND after install. Exiting."
                    exit 1
                fi
                echo "Command $cmd_to_check (for $pkg) verified after install."
            fi
        else
            echo "dnf install -y $pkg FAILED. Exit code: $?. Exiting."
            exit 1
        fi
    fi
done

echo "Verifying SELinux status and configuration..."
sestatus
if grep -q "^SELINUX=disabled" /etc/selinux/config; then
    echo "SELINUX is disabled in config. Changing to permissive."
    sed -i 's/^SELINUX=disabled/SELINUX=permissive/' /etc/selinux/config
elif ! grep -q "^SELINUX=" /etc/selinux/config; then
    echo "SELINUX line not found in config. Adding SELINUX=permissive."
    echo "SELINUX=permissive" >> /etc/selinux/config
else
    CURRENT_SELINUX_CONFIG=$(grep "^SELINUX=" /etc/selinux/config)
    echo "Current SELinux configuration in /etc/selinux/config: $CURRENT_SELINUX_CONFIG"
fi
echo "Final SELinux configuration in /etc/selinux/config:"
grep "^SELINUX=" /etc/selinux/config || echo "PROV_SYS: SELINUX line not found"
echo "SELinux status and configuration verified."

echo "Configuring passwordless sudo for the lima user..."
mkdir -p /etc/sudoers.d
echo "%lima ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/lima
chmod 440 /etc/sudoers.d/lima
