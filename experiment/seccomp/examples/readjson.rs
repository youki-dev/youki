use anyhow::Result;
#[path = "../tests/testutil.rs"]
mod testutil;

fn main() -> Result<()> {
    if let Err(e) = testutil::generate_seccomp_instruction("tests/default_x86_64.json".as_ref()) {
        eprintln!("Something wrong : {}", e);
    }
    Ok(())
}
