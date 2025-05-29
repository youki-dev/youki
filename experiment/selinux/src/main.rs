use selinux::selinux::*;
use selinux::selinux_label::*;
use std::env;
use std::fs::File;

fn main() -> Result<(), SELinuxError> {
    let mut selinux_instance: SELinux = SELinux::new();

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

    // Create temporary file in a directory we're likely to have permissions for
    let temp_dir = env::temp_dir();
    let file_path = temp_dir.join("selinux_test_file.txt");
    let _file = match File::create(&file_path) {
        Ok(file) => file,
        Err(e) => {
            println!("Warning: Could not create test file: {}", e);
            return Ok(());
        }
    };

    println!("Created test file at: {}", file_path.display());

    // Try to set SELinux label but handle permission errors gracefully
    let selinux_label =
        SELinuxLabel::try_from("system_u:object_r:public_content_t:s0".to_string())?;

    match SELinux::set_file_label(&file_path, selinux_label) {
        Ok(_) => {
            // Only try to get the label if setting it succeeded
            match SELinux::file_label(&file_path) {
                Ok(label) => println!("File label is {}", label),
                Err(e) => println!("Could not get file label: {}", e),
            }
        }
        Err(e) => {
            println!("Warning: Could not set SELinux label: {}", e);
            println!("This is expected if running without root privileges or if SELinux is not available");
        }
    }

    // Clean up the test file
    if let Err(e) = std::fs::remove_file(&file_path) {
        println!("Warning: Could not remove test file: {}", e);
    }

    Ok(())
}
