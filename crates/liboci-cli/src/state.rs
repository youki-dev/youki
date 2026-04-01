use clap::Parser;

/// Show the container state
#[derive(Parser, Debug)]
pub struct State {
    /// Container identifier
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
