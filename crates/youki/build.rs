use anyhow::Result;
use vergen_gitcl::{Emitter, Gitcl, Rustc};

pub fn main() -> Result<()> {
    // git failing is possible as we might be building in a bare
    // repo without .git history ; which is why we have a workaround
    // rustc failure is rarer, and we do not have a workaround in place
    // so we only match for error of git, and bubble up all other errors
    // via ? do error out the build
    // also see https://github.com/rustyhorde/vergen/issues/174#issuecomment-3631861105
    if Emitter::default()
        .add_instructions(&Rustc::all_rustc())?
        .add_instructions(&Gitcl::all_git())
        .and_then(|emitter| emitter.emit())
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
