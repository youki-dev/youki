use clap::Args;

/// Return the features list for a container
/// This subcommand was introduced in runc by
/// https://github.com/opencontainers/runc/pull/3296
/// It is documented here:
/// https://github.com/opencontainers/runtime-spec/blob/main/features-linux.md
#[derive(Args, Debug)]
pub struct Features {}
