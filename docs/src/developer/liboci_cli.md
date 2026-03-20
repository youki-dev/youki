# liboci-cli

This crate was separated from original youki crate, and now contains a standalone implementation of structs needed for parsing commandline arguments for OCI-spec compliant runtime commandline interface. This is in turn used by youki to parse the command line arguments passed to it, but can be used in any other projects where there is need to parse OCI spec based commandline arguments.

This primarily uses the [crate clap-v4](https://docs.rs/clap/latest/clap/index.html) for parsing the actual commandline arguments given to the runtime.

You can refer to [OCI Commandline interface guide](https://github.com/opencontainers/runtime-tools/blob/master/docs/command-line-interface.md) to know more about the exact specification.
