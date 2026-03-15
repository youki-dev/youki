use clap::Parser;

/// Show the container state
#[derive(Parser, Debug)]
pub struct State {
    /// Identifier of the container
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
