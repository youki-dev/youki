# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
    config.vm.box = "bento/fedora-42"
    config.vm.synced_folder '.', '/vagrant', disabled: true

    config.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.cpus = 2
    end
    config.vm.provision "shell", inline: <<-SHELL
      set -e -u -o pipefail
      yum update -y
      yum install -y git gcc docker wget pkg-config systemd-devel dbus-devel elfutils-libelf-devel libseccomp-devel clang-devel openssl-devel just
      grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0"
      service docker start
    SHELL

    config.vm.provision "shell", privileged: false, inline: <<-SHELL
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      echo "export PATH=$PATH:$HOME/.cargo/bin" >> ~/.bashrc

      git clone https://github.com/containers/youki
    SHELL
  end
