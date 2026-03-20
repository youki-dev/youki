use clap::Args;

/// Start a previously created container
#[derive(Args, Debug)]
pub struct Start {
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
