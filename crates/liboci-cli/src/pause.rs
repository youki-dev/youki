use clap::Parser;

/// Suspend the processes within the container
#[derive(Parser, Debug)]
pub struct Pause {
    /// Identifier of the container
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
