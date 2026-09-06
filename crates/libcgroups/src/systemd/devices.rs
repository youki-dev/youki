use std::collections::HashMap;
use std::fs;

use oci_spec::runtime::{LinuxDeviceCgroup, LinuxDeviceType};

use crate::common::{ControllerOpt, default_allow_devices, default_devices};
use crate::systemd::controller::Controller;
use crate::systemd::dbus_native::serialize::{Structure, Variant};
use crate::v2::devices::emulator::Emulator;

pub struct Devices {}

#[derive(thiserror::Error, Debug)]
pub enum SystemdDevicesError {
    #[error("failed to read /proc/devices: {0}")]
    ProcDevices(#[from] std::io::Error),
}

impl Controller for Devices {
    type Error = SystemdDevicesError;

    fn apply(
        options: &ControllerOpt,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        Self::apply_devices(options, systemd_version, properties)
    }
}

impl Devices {
    fn apply_devices(
        options: &ControllerOpt,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdDevicesError> {
        // If no device rules are specified, leave systemd's default policy (auto) untouched.
        // DevicePolicy=strict is only applied when the OCI spec explicitly restricts devices.
        let devices = match options.resources.devices() {
            Some(d) if !d.is_empty() => d,
            _ => return Ok(()),
        };

        let mut emulator = Emulator::with_default_allow(false);
        emulator.add_rules(devices);

        if emulator.default_allow {
            // allow-all: DevicePolicy=auto lifts all restrictions without an explicit list
            properties.insert("DevicePolicy", Variant::String("auto".to_string()));
            properties.insert("DeviceAllow", Variant::ArrayStructSS(vec![]));
            return Ok(());
        }

        // Whitelist mode: append default container device rules on top of user-defined rules,
        // mirroring the v2 eBPF path so standard devices (/dev/null, /dev/full, etc.) are
        // always accessible inside the container.
        for d in default_devices()
            .iter()
            .map(LinuxDeviceCgroup::from)
            .chain(default_allow_devices())
        {
            emulator.add_rule(&d);
        }

        // Strict policy + explicit allow list.
        properties.insert("DevicePolicy", Variant::String("strict".to_string()));
        properties.insert("DeviceAllow", Variant::ArrayStructSS(vec![]));

        let mut allow_list: Vec<Structure<String>> = Vec::new();

        for rule in &emulator.rules {
            if !rule.allow() {
                // systemd's DeviceAllow is a pure whitelist — deny rules are not expressible.
                // This mirrors runc's behaviour: warn and skip.
                tracing::warn!(
                    "systemd DeviceAllow does not support deny rules; skipping rule {:?}",
                    rule
                );
                continue;
            }

            let typ = rule.typ().unwrap_or_default();
            let type_prefix = match typ {
                LinuxDeviceType::C => "char",
                LinuxDeviceType::B => "block",
                // type='a' (all) with allow=true is handled above via emulator.default_allow
                _ => continue,
            };

            let access = rule.access().as_deref().unwrap_or("rwm").to_string();

            let path = match (rule.major(), rule.minor()) {
                (None, _) => {
                    // Wildcard major → all devices of this type: "char-*" / "block-*"
                    format!("{type_prefix}-*")
                }
                (Some(major), None) => {
                    // Specific major, wildcard minor
                    if systemd_version >= 240 {
                        // systemd ≥240 understands "char-N" / "block-N" natively
                        format!("{type_prefix}-{major}")
                    } else {
                        // Older systemd: look up the device group name from /proc/devices
                        match find_device_group(typ, major as u64)? {
                            Some(name) => name,
                            None => {
                                tracing::warn!(
                                    "could not find device group for {type_prefix} major {major}; skipping rule",
                                );
                                continue;
                            }
                        }
                    }
                }
                (Some(major), Some(minor)) => {
                    // Exact device node: "/dev/char/M:N" or "/dev/block/M:N"
                    format!("/dev/{type_prefix}/{major}:{minor}")
                }
            };

            allow_list.push(Structure::new(path, access));
        }

        properties.insert("DeviceAllow", Variant::ArrayStructSS(allow_list));
        Ok(())
    }
}

/// Parse `/proc/devices` to find the device-group name for `(type, major)`.
///
/// The file has sections like:
/// ```text
/// Character devices:
///   1 mem
///   4 /dev/vc/0
///
/// Block devices:
///   8 sd
/// ```
///
/// Returns e.g. `Some("mem")` for (C, 1), or `None` if not found.
fn find_device_group(typ: LinuxDeviceType, major: u64) -> Result<Option<String>, SystemdDevicesError> {
    let content = fs::read_to_string("/proc/devices")?;
    let section_header = match typ {
        LinuxDeviceType::C => "Character devices:",
        LinuxDeviceType::B => "Block devices:",
        _ => return Ok(None),
    };

    let mut in_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == section_header {
            in_section = true;
            continue;
        }
        if in_section {
            if trimmed.is_empty() {
                in_section = false;
                continue;
            }
            if let Some((maj_str, name)) = trimmed.split_once(' ') {
                if let Ok(maj) = maj_str.trim().parse::<u64>() {
                    if maj == major {
                        return Ok(Some(name.trim().to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::{LinuxDeviceCgroupBuilder, LinuxDeviceType, LinuxResourcesBuilder};

    use crate::common::ControllerOpt;

    use super::*;

    fn make_opt(devices: Vec<oci_spec::runtime::LinuxDeviceCgroup>) -> ControllerOpt<'static> {
        let resources = Box::leak(Box::new(
            LinuxResourcesBuilder::default()
                .devices(devices)
                .build()
                .unwrap(),
        ));
        ControllerOpt {
            resources,
            freezer_state: None,
            oom_score_adj: None,
            disable_oom_killer: false,
        }
    }

    #[test]
    fn test_no_devices_sets_nothing() {
        let resources = Box::leak(Box::new(
            LinuxResourcesBuilder::default().build().unwrap(),
        ));
        let opt = ControllerOpt {
            resources,
            freezer_state: None,
            oom_score_adj: None,
            disable_oom_killer: false,
        };
        let mut props: HashMap<&str, Variant> = HashMap::new();
        Devices::apply_devices(&opt, 245, &mut props).unwrap();

        // No device rules → leave systemd's default (auto) untouched
        assert!(props.is_empty());
    }

    #[test]
    fn test_allow_all_sets_auto_policy() {
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .allow(true)
            .build()
            .unwrap();
        let opt = make_opt(vec![rule]);
        let mut props: HashMap<&str, Variant> = HashMap::new();
        Devices::apply_devices(&opt, 245, &mut props).unwrap();

        assert_eq!(
            props.get("DevicePolicy"),
            Some(&Variant::String("auto".to_string()))
        );
    }

    fn get_allow(props: &HashMap<&str, Variant>) -> Vec<Structure<String>> {
        match props.get("DeviceAllow") {
            Some(Variant::ArrayStructSS(v)) => v.clone(),
            _ => panic!("expected ArrayStructSS in DeviceAllow"),
        }
    }

    #[test]
    fn test_wildcard_major_char() {
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .allow(true)
            .access("rw")
            .build()
            .unwrap();
        let opt = make_opt(vec![rule]);
        let mut props: HashMap<&str, Variant> = HashMap::new();
        Devices::apply_devices(&opt, 245, &mut props).unwrap();

        let allow = get_allow(&props);
        // User-specified entry must be present; default rules will also be present.
        assert!(
            allow.contains(&Structure::new("char-*".to_string(), "rw".to_string())),
            "expected char-* rw in allow list, got {:?}",
            allow
        );
    }

    #[test]
    fn test_exact_device_node() {
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::B)
            .major(8_i64)
            .minor(0_i64)
            .allow(true)
            .access("rw")
            .build()
            .unwrap();
        let opt = make_opt(vec![rule]);
        let mut props: HashMap<&str, Variant> = HashMap::new();
        Devices::apply_devices(&opt, 245, &mut props).unwrap();

        let allow = get_allow(&props);
        assert!(
            allow.contains(&Structure::new("/dev/block/8:0".to_string(), "rw".to_string())),
            "expected /dev/block/8:0 rw in allow list, got {:?}",
            allow
        );
    }

    #[test]
    fn test_major_only_new_systemd() {
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .major(1_i64)
            .allow(true)
            .access("r")
            .build()
            .unwrap();
        let opt = make_opt(vec![rule]);
        let mut props: HashMap<&str, Variant> = HashMap::new();
        // systemd >= 240: expects "char-1"
        Devices::apply_devices(&opt, 245, &mut props).unwrap();

        let allow = get_allow(&props);
        assert!(
            allow.contains(&Structure::new("char-1".to_string(), "r".to_string())),
            "expected char-1 r in allow list, got {:?}",
            allow
        );
    }

    #[test]
    fn test_deny_rule_is_skipped() {
        // A deny rule without any allow rules: the deny entry must not appear in DeviceAllow.
        // Default device rules will still be present in the list.
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .allow(false)
            .access("rw")
            .build()
            .unwrap();
        let opt = make_opt(vec![rule]);
        let mut props: HashMap<&str, Variant> = HashMap::new();
        Devices::apply_devices(&opt, 245, &mut props).unwrap();

        let allow = get_allow(&props);
        // The deny rule (char-* rw) must not appear in the allow list.
        assert!(
            !allow.contains(&Structure::new("char-*".to_string(), "rw".to_string())),
            "deny rule must not appear in DeviceAllow, got {:?}",
            allow
        );
        // Default devices (e.g. char-* m from default_allow_devices) should be present.
        assert!(
            allow.contains(&Structure::new("char-*".to_string(), "m".to_string())),
            "expected default char-* m in allow list, got {:?}",
            allow
        );
    }
}
