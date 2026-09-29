mod default_symlinks_test;
use anyhow::{Context, Result};
pub use default_symlinks_test::get_default_symlinks_test;
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};

fn create_spec(args: &[&str]) -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(args.iter().map(|s| s.to_string()).collect::<Vec<String>>())
                .build()?,
        )
        .build()
        .context("failed to create spec")
}
