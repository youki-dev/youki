# Basic Usage

This explains using Youki as a low-level container runtime. Youki can be used by itself to create, start and run containers, but doing so can be tedious, and thus you might want to use a higher-level runtime with Youki set as its runtime, so that you can get a convenient and easy interface.

You can use Youki with Docker, or Podman, but for the purpose of the examples, we will illustrate using Docker.

Youki can run in two modes, namely rootful mode, and rootless mode. The primary difference from the user-perspective in these is that as the name suggests, rootless mode does not require root/admin permissions, while rootful mode needs the root permissions. Both of these are shown in the examples below.

#### Using youki with a high-level runtime

We will first see how to use Youki with a high-level runtime such as Docker. You can install Docker from [here](https://docs.docker.com/engine/install/).

By default, after installation the docker sets up so that its daemon process will start running in background after booting up. By default, this configures Docker to use its default low-level runtime, and to use Youki instead , we will first need to stop the running Docker daemon.

As Youki needs systemd to compile, this assumes that you are running on a systemd based system. So you an first check if the docker daemon is running or not by running

```console
sudo systemctl status docker
```

This will print a message showing if the daemon is active or not. If it is active, then you will need to stop it by running

```console
sudo systemctl stop docker
```

After this you need to manually restart the docker daemon, but with Youki as its runtime. To do this, run following command in the youki/ directory after building youki

```console
dockerd --experimental --add-runtime="youki=$(pwd)/youki" # run in the youki/scripts directory
```

This will start the daemon and hang up the console. You can either start this as a background process to continue using the same terminal, or use another terminal, which will make it easier to stop the docker daemon later.

In case you don't stop the original daemon, you can get an error message after previous command

```console
failed to start daemon: pid file found, ensure docker is not running or delete /var/run/docker.pid
```

Now that the docker daemon is running, you can use docker normally as you will, but you will be able to specify Youki as its low-level runtime to actually create, start and stop the containers.

You can try running a container such as

```console
docker run -it --rm --runtime youki busybox   # run a container
```

This will start a busybox container, and give access to terminal inside it.

After you are done, you can stop the docker daemon by sending it a signal, either by using `Ctrl` + `C` if you are running the process in another terminal, or by using kill command with the pid of it, if you have started it as a background process.

Then to start the original/normal Docker daemon, you can run

```console
sudo systemctl start docker
```

#### Let docker permanently know youki as a runtime

With newer versions of docker, you can update file `/etc/docker/daemon.json` to
let docker know youki
([source](https://docs.docker.com/engine/reference/commandline/dockerd/#on-linux)).
You may need to create this file, if it does not yet exist. A sample content of it:

```json
{
  "default-runtime": "runc",
  "runtimes": {
    "youki": {
      "path": "/path/to/youki/youki",
      "runtimeArgs": [
          "--debug",
          "--systemd-log"
      ]
    }
  }
}
```

After this (need to restart docker at the first time), you can use youki
with docker: `docker run --runtime youki ...`. You can verify the runtime includes `youki`:

```console
$ docker info|grep -i runtime
 Runtimes: youki runc
 Default Runtime: runc
```

#### Using Youki Standalone

Youki can also be used directly, without a higher-level runtime such as Docker to create, start, stop and delete the container, but the process can be tedious. Here we will show how you can do that, to run a simple container with desired program running in it.

Note that we will still be using Docker to generate the rootfs required for running the container.

To start, in the youki/scripts directory, make another directory named tutorial, and create a sub-directory rootfs inside it

```console
mkdir -p tutorial/rootfs
```

After that, you will need to use docker to create the required directory structure

```console
cd tutorial
docker export $(docker create busybox) | tar -C rootfs -xvf -
```

This will create the required directory structure for using it as a root directory inside the container.

Now the any container runtime gets the information about the permissions, configurations and constraints for the container process by using a config.json file. Youki has a command which can generate the default config for you. To do this, run

```console
../youki spec
```

After this, you can manually edit the file to customize the behavior of the container process. For example, to run the desired program inside the container, you can edit the process.args

```json
"process": {
...
"args": [
  "sleep", "30"
],
...
 }
```

Here you can change the args to specify the program to be run, and arguments to be given to it.

After this, go back to the youki/ directory

```console
cd ..
```

As the setup is complete, you can now use youki to create the container, start the container, get its state etc.

```console
# create a container with name `tutorial_container`
sudo ./youki create -b tutorial tutorial_container

# you can see the state the container is `created`
sudo ./youki state tutorial_container

# start the container
sudo ./youki start tutorial_container

# will show the list of containers, the container is `running`
sudo ./youki list

# delete the container
sudo ./youki delete tutorial_container
```

The example above shows how to run Youki in a 'rootful' way. To run it without root permissions, that is, in rootless mode, few changes are required.

First, after exporting the rootfs from docker, while generating the config, you will need to pass the rootless flag. This will generate the config withe the options needed for rootless operation of the container.

```console
../youki spec --rootless
```

After this, the steps are basically the same, except you do not need to use sudo while running youki.

```console
cd ..
./youki create -b tutorial rootless_container
./youki state rootless_container
./youki start rootless_container
./youki list
./youki delete rootless_container
```

#### Log level

`youki` defaults the log level to `error` in the release build. In the debug
build, the log level defaults to `debug`. The `--log-level` flag can be used to
set the log-level. For least amount of log, we recommend using the `error` log
level. For the most spammy logging, we have a `trace` level.

For compatibility with `runc` and `crun`, we have a `--debug` flag to set the
log level to `debug`. This flag is ignored if `--log-level` is also set.
