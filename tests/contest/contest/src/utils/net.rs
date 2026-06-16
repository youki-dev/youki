use anyhow::{Result, anyhow};

pub fn create_unique_name(prefix: &str) -> String {
    let random_part: u16 = rand::random();
    format!("{}{}", prefix, random_part)
}

pub fn create_netns(name: &str) -> Result<()> {
    // Ensure /run/netns mount propagation is shared before creating netns
    // This is needed in case previous tests changed mount propagation to private
    let _ = std::process::Command::new("mount")
        .args(vec!["--make-shared", "/"])
        .output();

    let output = std::process::Command::new("ip")
        .args(vec!["netns", "add", name])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to create netns: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

pub fn cleanup_netns(name: &str) -> Result<()> {
    // Ensure /run/netns mount propagation is shared before deleting netns
    // This is needed in case previous tests changed mount propagation to private
    let _ = std::process::Command::new("mount")
        .args(vec!["--make-shared", "/"])
        .output();

    let output = std::process::Command::new("ip")
        .args(vec!["netns", "del", name])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "Failed to cleanup netns: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

pub fn create_dummy_device(name: &str) -> Result<()> {
    let output = std::process::Command::new("ip")
        .args(vec!["link", "add", name, "type", "dummy"])
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "Failed to create dummy device: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

pub fn delete_dummy_device(name: &str) -> Result<()> {
    let output = std::process::Command::new("ip")
        .args(vec!["link", "del", name])
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "Failed to delete dummy device: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// RAII guard for dummy network devices that automatically cleans up on drop
pub struct DummyDevice {
    name: String,
}

impl DummyDevice {
    pub fn create(name: String) -> Result<Self> {
        create_dummy_device(&name)?;
        Ok(Self { name })
    }
}

impl Drop for DummyDevice {
    fn drop(&mut self) {
        let _ = delete_dummy_device(&self.name);
    }
}

/// RAII guard for network namespaces that automatically cleans up on drop
pub struct NetNamespace {
    name: String,
}

impl NetNamespace {
    pub fn create(name: String) -> Result<Self> {
        create_netns(&name)?;
        Ok(Self { name })
    }
}

impl Drop for NetNamespace {
    fn drop(&mut self) {
        let _ = cleanup_netns(&self.name);
    }
}
