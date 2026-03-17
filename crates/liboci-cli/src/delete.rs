use clap::Parser;

/// Release any resources held by the container
#[derive(Parser, Debug)]
pub struct Delete {
    /// Container identifier
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// forces deletion of the container if it is still running (using SIGKILL)
    #[clap(short, long)]
    pub force: bool,
}
