use std::path::PathBuf;

use clap::Args;

/// Command generates a config.json
#[derive(Args, Debug)]
pub struct Spec {
    /// Set path to the root of the bundle directory
    #[arg(long, short)]
    pub bundle: Option<PathBuf>,

    /// Generate a configuration for a rootless container
    #[arg(long)]
    pub rootless: bool,
}
