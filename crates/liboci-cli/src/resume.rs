use clap::Args;

/// Resume the processes within the container
#[derive(Args, Debug)]
pub struct Resume {
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}
