use clap::Args;

/// List created containers
#[derive(Args, Debug)]
pub struct List {
    /// Specify the format (default or table)
    #[arg(long, default_value = "table")]
    pub format: String,

    /// Only display container IDs
    #[arg(long, short)]
    pub quiet: bool,
}
