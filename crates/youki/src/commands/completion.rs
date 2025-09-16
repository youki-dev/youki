use std::io;

use anyhow::Result;
use clap::{Command, Parser};
use clap_complete::{Shell, generate};

#[derive(Debug, Parser)]
/// Generate scripts for shell completion
pub struct Completion {
    #[clap(long = "shell", short = 's', value_enum)]
    pub shell: Shell,
}

pub fn completion(args: Completion, app: &mut Command) -> Result<()> {
    generate(
        args.shell,
        app,
        app.get_name().to_string(),
        &mut io::stdout(),
    );

    Ok(())
}
