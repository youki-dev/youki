use clap::Args;

/// Show resource statistics for the container
#[derive(Args, Debug)]
pub struct Events {
    /// Sets the stats collection interval in seconds (default: 5s)
    #[arg(long, default_value = "5")]
    pub interval: u32,
    /// Display the container stats only once
    #[arg(long)]
    pub stats: bool,
    /// Name of the container instance
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
