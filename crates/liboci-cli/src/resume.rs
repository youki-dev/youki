use clap::Parser;

/// Resume the processes within the container
#[derive(Parser, Debug)]
pub struct Resume {
    /// Container identifier
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
