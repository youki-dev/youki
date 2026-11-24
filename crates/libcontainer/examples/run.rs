//! Creates a container from an OCI bundle, starts it, and deletes it.
//!
//! ```console
//! cargo build -p libcontainer --example run
//! sudo target/debug/examples/run <container-id> <bundle>
//! ```

use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(id), Some(bundle)) = (args.next(), args.next()) else {
        return Err("usage: run <container-id> <bundle>".into());
    };

    let (mut container, _pty) = ContainerBuilder::new(id, SyscallType::default())
        .with_root_path("/run/youki-example")?
        .as_init(bundle)
        .with_systemd(false)
        .with_detach(true)
        .build()?;
    println!("{}: {}", container.id(), container.status());

    container.start()?;
    println!("{}: {}", container.id(), container.status());

    container.delete(true)?;
    Ok(())
}
