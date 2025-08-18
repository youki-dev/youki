#!/bin/bash
set -e

# Since systemd is not running inside the Dev Container,
# but the default events_logger for podman is set to journald, container startup fails.
# Therefore, change it to file.
sudo sed -i 's/^# events_logger = "journald"/events_logger = "file"/' /usr/share/containers/containers.conf
# Check events_logger setting
echo "events_logger: $(sudo podman info --format '{{.Host.EventLogger}}')"
