use clap::{self, Args};

/// Display the processes inside the container
#[derive(Args, Debug)]
pub struct Ps {
    /// format to display processes: table or json (default: "table")
    #[arg(short, long, default_value = "table")]
    pub format: String,
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// options will be passed to the ps utility
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub ps_options: Vec<String>,
}
