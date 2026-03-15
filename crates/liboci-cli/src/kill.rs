use clap::Parser;

/// Send the specified signal to the container
#[derive(Parser, Debug)]
pub struct Kill {
    /// Identifier of the container
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// Signal to send to the container (e.g. KILL, TERM, 9)
    pub signal: String,
    /// Send the signal to all processes inside the container
    #[clap(short, long)]
    pub all: bool,
}
