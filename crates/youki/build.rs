use anyhow::Result;
use vergen_gitcl::{Emitter, GitclBuilder};

pub fn main() -> Result<()> {
    if Emitter::default()
        .add_instructions(&GitclBuilder::all_git()?)?
        .emit()
        .is_err()
    {
        // currently we only inject git sha, so just this
        // else we will need to think of more elegant way to check
        // what failed, and what needs to be added
        println!("cargo:rustc-env=VERGEN_GIT_SHA=unknown");
    }

    // Embed rustc version at build time
    // Use RUSTC env var if set (for cross compilation), otherwise default to "rustc"
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let rustc_version = std::process::Command::new(&rustc)
        .arg("-V")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout);
                s.split_whitespace().nth(1).map(|v| v.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=RUSTC_VERSION={}", rustc_version);

    Ok(())
}
