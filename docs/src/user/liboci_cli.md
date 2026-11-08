# liboci-cli

This module provides the structs for command line arguments for OCI container runtimes as specified in the OCI Runtime Command Line Interface. The exposed structures derive `clap::Parser`, so that they can be directly used for parsing oci-commandline arguments.

### Implemented subcommands

|  Command   | liboci-cli | CLI Specification | runc | crun | youki |
| :--------: | :--------: | :---------------: | :--: | :--: | :---: |
|   create   |     ✅     |        ✅         |  ✅  |  ✅  |  ✅   |
|   start    |     ✅     |        ✅         |  ✅  |  ✅  |  ✅   |
|   state    |     ✅     |        ✅         |  ✅  |  ✅  |  ✅   |
|    kill    |     ✅     |        ✅         |  ✅  |  ✅  |  ✅   |
|   delete   |     ✅     |        ✅         |  ✅  |  ✅  |  ✅   |
| checkpoint |            |                   |  ✅  |  ✅  |       |
|   events   |     ✅     |                   |  ✅  |      |  ✅   |
|    exec    |     ✅     |                   |  ✅  |  ✅  |  ✅   |
|  features  |     ✅     |                   |  ✅  |  ✅  |  ✅   |
|    list    |     ✅     |                   |  ✅  |  ✅  |  ✅   |
|   pause    |     ✅     |                   |  ✅  |  ✅  |  ✅   |
|     ps     |     ✅     |                   |  ✅  |  ✅  |  ✅   |
|  restore   |            |                   |  ✅  |  ✅  |       |
|   resume   |     ✅     |                   |  ✅  |  ✅  |  ✅   |
|    run     |     ✅     |                   |  ✅  |  ✅  |  ✅   |
|    spec    |     ✅     |                   |  ✅  |  ✅  |  ✅   |
|   update   |     ✅     |                   |  ✅  |  ✅  |  ✅   |

youki's `update` applies `--resources` (which overrides the other flags), or else `--blkio-weight` and `--pids-limit`; it accepts the other resource flags but does not apply them.
