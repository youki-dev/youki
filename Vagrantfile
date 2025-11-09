# -*- mode: ruby -*-
# vi: set ft=ruby :

CONTAINERD_2_YOUKI_GO_VERSION = "1.20.12"
CONTAINERD_2_YOUKI_CONTAINERD_VERSION = "1.7.11"

PODMAN_E2E_GO_VERSION = "1.22.0"
PODMAN_E2E_PODMAN_BRANCH = "main"
PODMAN_E2E_SKOPEO_VERSION = "1.13.1"

Vagrant.configure("2") do |config|
  config.vm.define "default" do |m|
    m.vm.box = "bento/fedora-42"
    m.vm.synced_folder '.', '/vagrant', disabled: true

    m.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.cpus = 2
    end
    m.vm.provision "shell", inline: <<-SHELL
      set -e -u -o pipefail
      yum update -y
      yum install -y git gcc docker wget pkg-config systemd-devel dbus-devel elfutils-libelf-devel libseccomp-devel clang-devel openssl-devel just
      grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0"
      service docker start
    SHELL

    m.vm.provision "shell", privileged: false, inline: <<-SHELL
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      echo "export PATH=$PATH:$HOME/.cargo/bin" >> ~/.bashrc

      git clone https://github.com/youki-dev/youki
    SHELL
  end

  config.vm.define "rootful" do |m|
    m.vm.box = "bento/fedora-42"
    m.vm.synced_folder '.', '/vagrant', disabled: true

    m.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.cpus = 2
    end
    m.vm.provision "shell", path: "./hack/set_root_login_for_vagrant.sh"
    m.vm.provision "shell", inline: <<-SHELL
      set -e -u -o pipefail
      yum update -y
      yum install -y git gcc docker wget pkg-config systemd-devel dbus-devel elfutils-libelf-devel libseccomp-devel clang-devel openssl-devel just
      grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0"
      service docker start
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      echo "export PATH=$PATH:$HOME/.cargo/bin" >> ~/.bashrc
    SHELL
    m.ssh.username = 'root'
    m.ssh.insert_key = 'true'
  end

  config.vm.define "containerd2youki" do |m|
    m.vm.box = "bento/ubuntu-24.04"
    m.vm.synced_folder '.', '/vagrant/youki', disabled: false

    m.vm.provider "virtualbox" do |v|
      v.memory = 4096
      v.cpus = 4
    end

    m.vm.provision "bootstrap", type: "shell" do |s|
      s.inline = <<-SHELL
        set -e -u -o pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update && apt-get install -y \
          make \
          pkg-config         \
          libsystemd-dev     \
          libdbus-glib-1-dev \
          build-essential    \
          libelf-dev \
          libseccomp-dev \
          libbtrfs-dev \
          btrfs-progs
        
        ARCH=$(uname -m)
        case "$ARCH" in
          x86_64)
            GOARCH="amd64"
            ;;
          aarch64)
            GOARCH="arm64"
            ;;
          *)
            echo "Unsupported architecture: $ARCH"
            exit 1
            ;;
        esac
        
        wget --quiet https://go.dev/dl/go#{CONTAINERD_2_YOUKI_GO_VERSION}.linux-${GOARCH}.tar.gz -O /tmp/go#{CONTAINERD_2_YOUKI_GO_VERSION}.linux-${GOARCH}.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go#{CONTAINERD_2_YOUKI_GO_VERSION}.linux-${GOARCH}.tar.gz
        echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
        echo "export GOPATH=$HOME/go" >> ~/.bashrc
        export PATH=$PATH:$HOME/.cargo/bin:/usr/local/go/bin
        export GOPATH=$HOME/go

        git clone https://github.com/containerd/containerd \
          /root/go/src/github.com/containerd/containerd -b v#{CONTAINERD_2_YOUKI_CONTAINERD_VERSION}

        cd /root/go/src/github.com/containerd/containerd
        make
        make binaries
        make install
        ./script/setup/install-cni
        ./script/setup/install-critools
        rm -rf /bin/runc /sbin/runc /usr/sbin/runc /usr/bin/runc
        ln -s /vagrant/youki/youki /usr/bin/runc
      SHELL
    end

    m.vm.provision "test", type: "shell", run: "never" do |s|
        s.inline = <<-SHELL
          export RUNC_FLAVOR=crun
          cd /root/go/src/github.com/containerd/containerd/
          export PATH=$PATH:$HOME/.cargo/bin:/usr/local/go/bin
          make TEST_RUNTIME=io.containerd.runc.v2 TESTFLAGS="-timeout 120m" integration | tee result.txt
          grep "FAIL: " result.txt || true
        SHELL
    end
  end

  config.vm.define "podmane2e" do |m|
    m.vm.box = "bento/ubuntu-24.04"
    m.vm.synced_folder '.', '/vagrant/youki', disabled: false

    m.vm.provider "virtualbox" do |v|
      v.memory = 8192
      v.cpus = 8
    end

    m.vm.provision "bootstrap", type: "shell" do |s|
      s.inline = <<-SHELL
        set -e -u -o pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update && apt-get install -y \
          make \
          pkg-config         \
          libsystemd-dev     \
          libdbus-glib-1-dev \
          build-essential    \
          libelf-dev \
          libseccomp-dev \
          libbtrfs-dev \
          btrfs-progs \
          libgpgme-dev \
          libassuan-dev \
          libdevmapper-dev \
          bats \
          socat \
          jq \
          conmon \
          protobuf-compiler

        ARCH=$(uname -m)
        case "$ARCH" in
          x86_64)
            GOARCH="amd64"
            ;;
          aarch64)
            GOARCH="arm64"
            ;;
          *)
            echo "Unsupported architecture: $ARCH"
            exit 1
            ;;
        esac

        wget --quiet https://go.dev/dl/go#{PODMAN_E2E_GO_VERSION}.linux-${GOARCH}.tar.gz -O /tmp/go#{PODMAN_E2E_GO_VERSION}.linux-${GOARCH}.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go#{PODMAN_E2E_GO_VERSION}.linux-${GOARCH}.tar.gz
        echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
        echo "export GOPATH=$HOME/go" >> ~/.bashrc
        export PATH=$PATH:$HOME/.cargo/bin:/usr/local/go/bin
        export GOPATH=$HOME/go

        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        cargo install netavark aardvark-dns
        mkdir -p /usr/local/lib/podman
        sudo cp $(which netavark) /usr/local/lib/podman/
        sudo cp $(which netavark)-dhcp-proxy-client /usr/local/lib/podman/
        sudo cp $(which aardvark-dns) /usr/local/lib/podman/

        mkdir /tmp/skopeo 
        curl -fsSL "https://github.com/containers/skopeo/archive/v#{PODMAN_E2E_SKOPEO_VERSION}.tar.gz" | tar -xzf - -C /tmp/skopeo --strip-components=1
        cd /tmp/skopeo && DISABLE_DOCS=1 make
        sudo mkdir /etc/containers && sudo cp /tmp/skopeo/bin/skopeo /usr/local/bin/skopeo && sudo cp /tmp/skopeo/default-policy.json /etc/containers/policy.json

        git clone https://github.com/containers/podman /vagrant/podman -b #{PODMAN_E2E_PODMAN_BRANCH}
        
        cd /vagrant/podman && make binaries install.tools

        rm -rf /bin/runc /sbin/runc /usr/sbin/runc /usr/bin/runc

        cp /vagrant/youki/youki /usr/bin/runc
      SHELL
    end
  end
end
