# User Documentation

This section provides documentation of youki and the sub crates that the youki repo contains for the users. So if you are using youki as a low level container runtime, or using any of the crates in youki workspace as dependencies for your own project, this section might be helpful for you.

This is divided into following sub-sections :

- Basic Setup : This explains how the dependencies and setup required to compile and run youki
- Basic Usage : This explains using youki itself as a low-level container runtime, or using one of the crates as dependencies
- crates : This section provides brief explanation of the member crates of youki repo workspace
  - libcgroups
  - libcontainer
  - liboci-cli
  - libseccomp
- Webassembly : This explains how to use webassembly module with youki.
- Kubernetes : This explains how to install youki on a Kubernetes cluster as the OCI runtime via the youki-deploy DaemonSet.
