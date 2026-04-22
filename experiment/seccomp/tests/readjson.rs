#[path = "./helpers/mod.rs"]
mod utils;

#[test]
fn read_json() {
    if let Err(e) =
        utils::generate_seccomp_instruction("tests/fixtures/default_x86_64.json".as_ref())
    {
        eprintln!("Something wrong : {}", e);
    }
}
