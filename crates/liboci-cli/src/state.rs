use clap::Args;

/// Show the container state
#[derive(Args, Debug)]
pub struct State {
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
