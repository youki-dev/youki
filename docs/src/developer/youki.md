# youki

This is the core crate that contains the youki binary itself. This provides the user interface, as well as binds the other crates together to actually perform the work of creation and management of containers. Thus, this provides implementation of all the commands supported by youki.

The simple control flow of youki can be explained as :

<p align="center">
  <img src="../assets/control_flow.drawio.svg">
</p>

When given the create command, Youki will load the specification, configuration, sockets etc., and use clone syscall to create an intermediate process. This process will set the cgroups and capabilities, and then fork to the init process. Reason to create this intermediate process is that the clone syscall cannot enter into existing pid namespace that has been created for the container. Thus first we need to make a transition to that namespace in the intermediate process and fork that to the container process. After that the main youki process is requested the uid and gid mappings, and after receiving them the intermediate process sets these mapping, fork the init process and return pid of this init process to the main youki process before exiting.

The init process then transition completely into the new namespace setup for the container (the init process only transitions the pid namespace). It changes the root mountpoint for the process using [pivot_root](https://man7.org/linux/man-pages/man2/pivot_root.2.html), so that the container process can get impression that it has a complete root path access. After that the init process sets up the capabilities and seccomp, and sends the seccomp notify fd to the main youki process. When the seccomp agent running on the host system sets up the seccomp profile, it notifies the init process, after which it can execute the program inside the container. Thus the init process then sends ready notification to the main youki process, and waits for the start signal.

The main youki process which started creating the container, when receives the ready signals update the pid file of the container process and exits. This concludes the creation of the container.

To start the container, when youki start it executed along with the container id, start signal is sent to the waiting container init process, and the the youki process exists.

When the init process receives the start signal, it execs the program to be run in the container, and then exits.

### Notes

The main youki process will set up pipes used as message passing and synchronization mechanism with the init process. The reason youki needs to create/fork two process instead of one is due to the user and pid namespaces. In rootless container, we need to first enter user namespace, since all other namespaces requires CAP_SYSADMIN. When unshare or set_ns into pid namespace, only the children of the current process will enter into a different pid namespace. As a result, we must first fork a process to enter into user namespace, call unshare or set_ns for pid namespace, then fork again to enter into the correct pid namespace.
