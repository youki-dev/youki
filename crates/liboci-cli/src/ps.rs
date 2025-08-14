use clap::{self, Parser};

/// Display the processes inside the container
#[derive(Parser, Debug)]
pub struct Ps {
    /// format to display processes: table or json (default: "table")
    #[clap(short, long, default_value = "table")]
    pub format: String,
    #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// options will be passed to the ps utility
    #[clap(trailing_var_arg = true)]
    pub ps_options: Vec<String>,
}
