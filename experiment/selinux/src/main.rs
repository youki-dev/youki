use selinux::selinux::*;
use selinux::selinux_label::*;
use std::fs::File;
use std::path::Path;

fn main() -> Result<(), SELinuxError> {
    let mut selinux_instance: SELinux = SELinux::new(Path::new(DEFAULT_SELINUX_DIR))?;

    if selinux_instance.get_enabled() {
        println!("selinux is enabled");
    } else {
        println!("selinux is not enabled");

        match selinux_instance.set_enforce_mode(SELinuxMode::PERMISSIVE) {
            Ok(_) => println!("set selinux mode as permissive"),
            Err(e) => println!("{}", e),
        }
    }
    println!(
        "default enforce mode is: {}",
        selinux_instance.default_enforce_mode()
    );
    println!(
        "current enforce mode is: {}",
        selinux_instance.enforce_mode()
    );

    match selinux_instance.current_label() {
        Ok(l) => println!("SELinux label of current process is: {}", l),
        Err(e) => println!("{}", e),
    }

    let file_path = Path::new("./test_file.txt");
    let _file = File::create(file_path).unwrap();
    let selinux_label =
        SELinuxLabel::try_from("system_u:object_r:public_content_t:s0".to_string())?;
    SELinux::set_file_label(file_path, selinux_label)?;
    let current_label = SELinux::file_label(file_path)?;
    println!("file label is {}", current_label);

    Ok(())
}
