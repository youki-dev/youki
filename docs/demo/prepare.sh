#!/usr/bin/env bash
# Runs inside the VM. Builds youki from this checkout and wires it into Docker and a kind cluster.
# Safe to run again: each step skips what is already in place.
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
out=/tmp/youki-demo
node=youki-control-plane

# The kind node is Debian bookworm, so build there. The same binary also runs on the VM.
if [ ! -x "$out/youki" ]; then
	mkdir -p "$out"
	# `youki --version` prints the commit, so the build needs the git directory.
	# In a worktree it lives outside the checkout.
	gitdir=$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir)
	docker run --rm -v "$repo:/src:ro" -v "$gitdir:$gitdir:ro" -v "$out:/out" -e CARGO_TARGET_DIR=/out/target \
		-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e 'GIT_CONFIG_VALUE_0=*' rust:1-bookworm bash -c '
		set -e
		apt-get update -qq
		apt-get install -y -qq --no-install-recommends pkg-config libsystemd-dev libelf-dev libseccomp-dev libclang-dev libssl-dev
		cd /src
		cargo build --release -p youki --features "v1 v2 systemd wasm-wasmtime"
		cp /out/target/release/youki /out/youki'
fi
sudo install -m 755 "$out/youki" /usr/local/bin/youki

if ! docker info --format '{{json .Runtimes}}' | grep -q '"youki"'; then
	echo '{"runtimes": {"youki": {"path": "/usr/local/bin/youki"}}}' | sudo tee /etc/docker/daemon.json >/dev/null
	sudo systemctl restart docker
fi

mkdir -p "$out/image"
cp "$repo/docs/demo/hello.wat" "$out/image/hello.wat"
printf 'FROM scratch\nCOPY hello.wat /\nENTRYPOINT ["/hello.wat"]\n' | docker build -q -t hello-wasm -f - "$out/image" >/dev/null
docker pull -q busybox >/dev/null

kind get clusters | grep -qx youki || kind create cluster --name youki
docker cp "$out/youki" "$node:/usr/local/bin/youki"
docker exec "$node" sh -c '
	grep -q runtimes.youki /etc/containerd/config.toml && exit 0
	cat >>/etc/containerd/config.toml <<TOML
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.youki]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.youki.options]
    BinaryName = "/usr/local/bin/youki"
    SystemdCgroup = true
TOML
	systemctl restart containerd'
kubectl wait --for=condition=Ready node --all --timeout=120s
kubectl apply -f "$repo/tests/k8s/runtimeclass.yaml"
docker exec "$node" crictl pull docker.io/library/nginx:alpine >/dev/null
