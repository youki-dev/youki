use anyhow::Result;
use vergen_gitcl::{Emitter, GitclBuilder, RustcBuilder};

pub fn main() -> Result<()> {
    if Emitter::default()
        .add_instructions(&GitclBuilder::all_git()?)?
        .add_instructions(&RustcBuilder::all_rustc()?)?
        .emit()
        .is_err()
    {
        // currently we only inject git sha, so just this
        // else we will need to think of more elegant way to check
        // what failed, and what needs to be added
        println!("cargo:rustc-env=VERGEN_GIT_SHA=unknown");
        println!("cargo:rustc-env=VERGEN_RUSTC_SEMVER=unknown");
    }

    // Embed libseccomp version at build time (only when seccomp feature is enabled)
    if std::env::var("CARGO_FEATURE_SECCOMP").is_ok() {
        let version = pkg_config::probe_library("libseccomp")
            .map(|lib| lib.version)
            .unwrap_or_else(|_| "unknown".to_string());
        println!("cargo:rustc-env=LIBSECCOMP_VERSION={}", version);
    }

    Ok(())
}
