use clap::Args;

/// Suspend the processes within the container
#[derive(Args, Debug)]
pub struct Pause {
    /// Container identifier
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
