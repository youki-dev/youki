use clap::Args;

/// Send the specified signal to the container
#[derive(Args, Debug)]
pub struct Kill {
    /// Container identifier
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// Signal to send to the container (e.g. KILL, TERM, 9)
    pub signal: String,
    /// Send the signal to all processes inside the container
    #[arg(short, long)]
    pub all: bool,
}
