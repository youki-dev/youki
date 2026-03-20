use clap::Args;

/// Send the specified signal to the container
#[derive(Args, Debug)]
pub struct Kill {
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    pub signal: String,
    #[arg(short, long)]
    pub all: bool,
}
