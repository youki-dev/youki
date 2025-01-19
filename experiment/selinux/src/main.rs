use std::fs::File;
use std::path::Path;

use selinux::{label::*, selinux::*, setting::SELinuxSetting, SELinuxError, SELinuxMode};

fn main() -> Result<(), SELinuxError> {
    let setting = SELinuxSetting::try_default()?;
    println!("current enforce mode is: {}", setting.enforce_mode()?);

    let selinux: SELinux = SELinux::try_default(&setting)?;
    if selinux.get_enabled() {
        println!("SELinux is enabled");
    } else {
        println!("SELinux is not enabled");
        match setting.set_enforce_mode(SELinuxMode::PERMISSIVE) {
            Ok(_) => println!("set selinux mode as permissive"),
            Err(e) => return Err(SELinuxError::from(e)),
        };
    }

    match selinux.current_label() {
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
