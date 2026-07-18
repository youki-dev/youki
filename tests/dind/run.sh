#!/bin/bash
set -e

ROOT=$(git rev-parse --show-toplevel)

# Pin the DinD image to a known-working Docker version for CI reproducibility.
#
# Docker 29.5 enables time namespaces by default, which youki does not
# support yet. Do not move past Docker 29.4 until time namespace support is added.
docker run --privileged -dq \
  --name youki-test-dind \
  -v $ROOT/youki:/usr/bin/youki \
  -v $ROOT/tests/dind/daemon.json:/etc/docker/daemon.json \
  docker:29.4-dind > /dev/null

trap "docker rm -f youki-test-dind > /dev/null" EXIT

# wait for docker to start
timeout 30s \
  grep -q -m1 "/var/run/docker.sock" \
    <(docker logs -f youki-test-dind 2>&1)

docker exec -i youki-test-dind \
  docker run -q --runtime=youki hello-world
