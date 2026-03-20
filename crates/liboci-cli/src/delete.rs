use clap::Args;

/// Release any resources held by the container
#[derive(Args, Debug)]
pub struct Delete {
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// forces deletion of the container if it is still running (using SIGKILL)
    #[arg(short, long)]
    pub force: bool,
}
