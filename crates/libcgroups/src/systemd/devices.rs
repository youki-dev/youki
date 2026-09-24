use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use oci_spec::runtime::{LinuxDeviceCgroup, LinuxDeviceType};

use crate::common::{ControllerOpt, default_allow_devices, default_devices};
use crate::systemd::controller::Controller;
use crate::systemd::dbus_native::serialize::{Structure, Variant};
use crate::v2::devices::emulator::Emulator;

const PROC_DEVICES: &str = "/proc/devices";

pub struct Devices {}

#[derive(thiserror::Error, Debug)]
pub enum SystemdDevicesError {
    #[error("failed to read {path}: {err}")]
    ProcDevices { path: String, err: std::io::Error },
    #[error("device rule type {0:?} has no device cgroup equivalent")]
    UnsupportedDeviceType(LinuxDeviceType),
}

/// The access a DeviceAllow entry grants, merged over the rules naming its path.
///
/// systemd keeps the last entry for a path instead of merging, so rules have to arrive
/// merged. runc gets this from its emulator, which keeps one rule per device.
#[derive(Clone, Copy, Default)]
struct Access {
    read: bool,
    write: bool,
    mknod: bool,
}

impl Access {
    fn is_empty(&self) -> bool {
        !(self.read || self.write || self.mknod)
    }

    fn add(&mut self, access: &str) {
        for flag in access.chars() {
            match flag {
                'r' => self.read = true,
                'w' => self.write = true,
                'm' => self.mknod = true,
                _ => {}
            }
        }
    }
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (granted, flag) in [(self.read, 'r'), (self.write, 'w'), (self.mknod, 'm')] {
            if granted {
                write!(f, "{flag}")?;
            }
        }
        Ok(())
    }
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
        Self::apply_devices_from(PROC_DEVICES, options, systemd_version, properties)
    }

    /// Takes the `/proc/devices` path so the tests can reach the paths that read it.
    fn apply_devices_from(
        proc_devices: &str,
        options: &ControllerOpt,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdDevicesError> {
        // An absent rule list is not a request for unrestricted access, and the cgroupfs
        // path (v2::devices::controller) does not read it as one either.
        let devices = options.resources.devices().as_deref().unwrap_or_default();

        let mut emulator = Emulator::with_default_allow(false);
        emulator.add_rules(devices);

        // A deny rule takes away access an earlier rule, or one of the defaults below,
        // grants, and the OCI spec requires the rules to be applied in order. A whitelist
        // cannot express that.
        let has_deny_rule = emulator.rules.iter().any(|rule| !rule.allow());

        if emulator.default_allow && !has_deny_rule {
            properties.insert("DevicePolicy", Variant::String("auto".to_string()));
            properties.insert("DeviceAllow", Variant::ArrayStructSS(vec![]));
            return Ok(());
        }

        // Whatever goes in the list has to be wrong for these rules, so it is made wrong in
        // the direction that cannot hand out access the spec refuses. What the container
        // really gets is the eBPF filter the manager attaches right afterwards, which
        // detaches the program systemd derives from this list; the list is what remains if
        // that attach never happens.
        if has_deny_rule {
            tracing::warn!(
                "systemd DeviceAllow cannot express deny rules; sending a deny-all list and \
                 leaving the rules to the eBPF device filter"
            );
            properties.insert("DevicePolicy", Variant::String("strict".to_string()));
            properties.insert("DeviceAllow", Variant::ArrayStructSS(vec![]));
            return Ok(());
        }

        // So standard devices (/dev/null, /dev/full, ...) stay accessible as in the eBPF
        // path.
        for d in default_devices()
            .iter()
            .map(LinuxDeviceCgroup::from)
            .chain(default_allow_devices())
        {
            emulator.add_rule(&d);
        }

        // Keyed by path so rules for one device arrive as a single entry, and ordered so the
        // properties come out the same every time.
        let mut allowed: BTreeMap<String, Access> = BTreeMap::new();

        for rule in &emulator.rules {
            let typ = rule.typ().unwrap_or_default();
            let type_prefix = match typ {
                LinuxDeviceType::C => "char",
                LinuxDeviceType::B => "block",
                // 'u' and 'p' have no device cgroup equivalent, so there is nothing to
                // send and no way to honour them. Dropping them would leave the caller
                // believing a rule took effect; the eBPF path errors on them too
                // (v2::devices::program). type='a' never reaches here.
                _ => {
                    return Err(SystemdDevicesError::UnsupportedDeviceType(typ));
                }
            };

            // A negative number is the spec's wildcard, read the same way by the eBPF
            // path, so a spec keeps its meaning whichever cgroup manager applies it.
            let major = rule.major().filter(|major| *major >= 0);
            let minor = rule.minor().filter(|minor| *minor >= 0);

            // Emulator::add_rule() drops rules without access, and systemd reads an entry
            // with no access as "rwm", so one must never reach the allow list.
            let Some(access) = rule.access().as_deref() else {
                continue;
            };

            let path = match (major, minor) {
                (None, None) => format!("{type_prefix}-*"),
                (None, Some(minor)) => {
                    // systemd names either a whole device group or one node, and the
                    // nearest thing to "any major, this minor" is the whole type, so the
                    // rule is dropped rather than turned into one that grants more.
                    tracing::warn!(
                        "systemd DeviceAllow does not support '*:{minor}' device rules; skipping rule {:?}",
                        rule
                    );
                    continue;
                }
                (Some(major), None) => {
                    if systemd_version >= 240 {
                        format!("{type_prefix}-{major}")
                    } else {
                        // Before 240 systemd only knows the names in /proc/devices.
                        match find_device_group(proc_devices, typ, major as u64)? {
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
                    let node = format!("/dev/{type_prefix}/{major}:{minor}");
                    // Before 240 systemd reads the device number off the path with
                    // stat(2), so an entry for a node that is not there is dropped with a
                    // warning from systemd. Leaving it out keeps that noise out of the
                    // journal for something already known here.
                    if systemd_version < 240 && !Path::new(&node).exists() {
                        tracing::warn!(
                            "systemd {systemd_version} needs {node} to exist to allow it; \
                             skipping rule {rule:?}",
                        );
                        continue;
                    }
                    node
                }
            };

            allowed.entry(path).or_default().add(access);
        }

        // Sending one of these would grant rwm, see above.
        let allow_list: Vec<Structure<String>> = allowed
            .into_iter()
            .filter(|(_, access)| !access.is_empty())
            .map(|(path, access)| Structure::new(path, access.to_string()))
            .collect();

        // Written only once the list is complete, so an error above cannot leave a strict
        // policy without one. The client clears the unit's existing DeviceAllow before it
        // sends this one, because systemd would otherwise append to it.
        properties.insert("DevicePolicy", Variant::String("strict".to_string()));
        properties.insert("DeviceAllow", Variant::ArrayStructSS(allow_list));
        Ok(())
    }
}

fn find_device_group(
    path: &str,
    typ: LinuxDeviceType,
    major: u64,
) -> Result<Option<String>, SystemdDevicesError> {
    let content = fs::read_to_string(path).map_err(|err| SystemdDevicesError::ProcDevices {
        path: path.to_string(),
        err,
    })?;
    Ok(find_device_group_in(&content, typ, major))
}

/// Find the device-group name for `(type, major)` in the contents of `/proc/devices`, as
/// systemd wants it: `Some("char-mem")` for (C, 1).
fn find_device_group_in(content: &str, typ: LinuxDeviceType, major: u64) -> Option<String> {
    let (section_header, prefix) = match typ {
        LinuxDeviceType::C => ("Character devices:", "char"),
        LinuxDeviceType::B => ("Block devices:", "block"),
        _ => return None,
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
                    let name = name.trim();
                    // A major can be listed twice, as "4 /dev/vc/0" and "4 tty" are. Only
                    // a group name works as a DeviceAllow entry, and it needs the device
                    // type as a prefix, so the node paths are skipped. That is stricter
                    // than runc's findDeviceGroup(), which returns whichever of the two it
                    // reaches first. Ref: systemd.exec(5) DeviceAllow=.
                    if maj == major && !name.contains('/') {
                        return Some(format!("{prefix}-{name}"));
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::{
        LinuxDeviceCgroupBuilder, LinuxDeviceType, LinuxResources, LinuxResourcesBuilder,
    };

    use super::*;
    use crate::common::ControllerOpt;

    const PROC_DEVICES_SAMPLE: &str = "\
Character devices:
  1 mem
  4 /dev/vc/0
  4 tty
136 pts

Block devices:
  7 loop
  8 sd
";

    fn resources(devices: Vec<LinuxDeviceCgroup>) -> LinuxResources {
        LinuxResourcesBuilder::default()
            .devices(devices)
            .build()
            .unwrap()
    }

    /// Writes `PROC_DEVICES_SAMPLE` out so the systemd < 240 path reads the fixture rather
    /// than the host's `/proc/devices`.
    fn proc_devices_fixture(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    fn try_apply_from(
        proc_devices: &str,
        resources: &LinuxResources,
        systemd_version: u32,
    ) -> Result<HashMap<&'static str, Variant>, SystemdDevicesError> {
        let opt = ControllerOpt {
            resources,
            freezer_state: None,
            oom_score_adj: None,
            disable_oom_killer: false,
        };
        let mut props: HashMap<&str, Variant> = HashMap::new();
        Devices::apply_devices_from(proc_devices, &opt, systemd_version, &mut props)?;
        Ok(props)
    }

    fn try_apply(
        resources: &LinuxResources,
        systemd_version: u32,
    ) -> Result<HashMap<&'static str, Variant>, SystemdDevicesError> {
        try_apply_from(PROC_DEVICES, resources, systemd_version)
    }

    fn apply(resources: &LinuxResources, systemd_version: u32) -> HashMap<&'static str, Variant> {
        try_apply(resources, systemd_version).unwrap()
    }

    fn get_policy(props: &HashMap<&str, Variant>) -> Option<String> {
        match props.get("DevicePolicy") {
            Some(Variant::String(s)) => Some(s.clone()),
            _ => None,
        }
    }

    fn get_allow(props: &HashMap<&str, Variant>) -> Vec<Structure<String>> {
        match props.get("DeviceAllow") {
            Some(Variant::ArrayStructSS(v)) => v.clone(),
            _ => panic!("expected ArrayStructSS in DeviceAllow"),
        }
    }

    fn entry(path: &str, access: &str) -> Structure<String> {
        Structure::new(path.to_string(), access.to_string())
    }

    #[test]
    fn test_no_devices_still_restricts() {
        // Leaving systemd's default in place would make a spec without device rules
        // unconfined here while the cgroupfs path confines it.
        let resources = LinuxResourcesBuilder::default().build().unwrap();
        let props = apply(&resources, 245);

        assert_eq!(get_policy(&props).as_deref(), Some("strict"));
        let allow = get_allow(&props);
        assert!(
            allow.contains(&entry("/dev/char/1:3", "rwm")),
            "expected the default rules to be applied, got {allow:?}"
        );
    }

    #[test]
    fn test_allow_all_sets_auto_policy() {
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .allow(true)
            .build()
            .unwrap();
        let props = apply(&resources(vec![rule]), 245);

        assert_eq!(get_policy(&props).as_deref(), Some("auto"));
        assert!(get_allow(&props).is_empty());
    }

    #[test]
    fn test_blacklist_with_deny_rule_falls_back_to_deny_all() {
        // Dropping the deny rule here would leave every device allowed, so the list has to
        // come out empty and leave the rules to the eBPF filter.
        let allow_all = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .allow(true)
            .build()
            .unwrap();
        let deny_char = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .allow(false)
            .access("rw")
            .build()
            .unwrap();
        let props = apply(&resources(vec![allow_all, deny_char]), 245);

        assert_eq!(get_policy(&props).as_deref(), Some("strict"));
        assert!(
            get_allow(&props).is_empty(),
            "expected an empty allow list, got {:?}",
            get_allow(&props)
        );
    }

    #[test]
    fn test_blacklist_with_redundant_allow_rule_stays_auto() {
        // "allow everything, then allow char devices" denies nothing, so allow-all is exact.
        let allow_all = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .allow(true)
            .build()
            .unwrap();
        let allow_char = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .allow(true)
            .access("rw")
            .build()
            .unwrap();
        let props = apply(&resources(vec![allow_all, allow_char]), 245);

        assert_eq!(get_policy(&props).as_deref(), Some("auto"));
    }

    #[test]
    fn test_wildcard_major_char() {
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .allow(true)
            .access("rw")
            .build()
            .unwrap();
        let props = apply(&resources(vec![rule]), 245);

        let allow = get_allow(&props);
        // The rule shares its path with the default "char-* m" rule, and systemd would keep
        // only the last entry for a path, so the two have to arrive merged.
        assert!(
            allow.contains(&entry("char-*", "rwm")),
            "expected char-* rwm in allow list, got {allow:?}"
        );
    }

    #[test]
    fn test_rules_for_the_same_path_are_merged() {
        let read = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::B)
            .major(8_i64)
            .minor(0_i64)
            .allow(true)
            .access("r")
            .build()
            .unwrap();
        let write = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::B)
            .major(8_i64)
            .minor(0_i64)
            .allow(true)
            .access("w")
            .build()
            .unwrap();
        let props = apply(&resources(vec![read, write]), 245);

        let allow = get_allow(&props);
        assert!(
            allow.contains(&entry("/dev/block/8:0", "rw")),
            "expected one merged /dev/block/8:0 rw entry, got {allow:?}"
        );
        assert_eq!(
            allow
                .iter()
                .filter(|e| **e == entry("/dev/block/8:0", "rw"))
                .count(),
            1,
            "expected a single entry per path, got {allow:?}"
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
        let props = apply(&resources(vec![rule]), 245);

        let allow = get_allow(&props);
        assert!(
            allow.contains(&entry("char-1", "r")),
            "expected char-1 r in allow list, got {allow:?}"
        );
    }

    #[test]
    fn test_wildcard_major_with_minor_is_skipped() {
        // "*:3" has no systemd representation and must not be widened to "char-*".
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .minor(3_i64)
            .allow(true)
            .access("rw")
            .build()
            .unwrap();
        let props = apply(&resources(vec![rule]), 245);

        let allow = get_allow(&props);
        assert!(
            !allow.contains(&entry("char-*", "rw")),
            "'*:3' must not become char-* rw, got {allow:?}"
        );
        // The default rules are still applied, so the list is not simply empty.
        assert!(
            allow.contains(&entry("char-*", "m")),
            "expected default char-* m in allow list, got {allow:?}"
        );
    }

    #[test]
    fn test_negative_major_is_a_wildcard() {
        // A negative major is the spec's wildcard, so it must widen the entry rather
        // than be printed as a device number.
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .major(-1_i64)
            .allow(true)
            .access("rw")
            .build()
            .unwrap();
        let props = apply(&resources(vec![rule]), 245);

        let allow = get_allow(&props);
        assert!(
            allow.contains(&entry("char-*", "rwm")),
            "expected the rule to be merged into char-* rwm, got {allow:?}"
        );
        assert!(
            !allow.iter().any(|e| *e == entry("char--1", "rw")),
            "a negative major must not be printed as a device number, got {allow:?}"
        );
    }

    #[test]
    fn test_unsupported_device_type_is_rejected() {
        // Nothing can be sent for these, so failing is the only way the caller learns
        // the rule did not take effect.
        for typ in [LinuxDeviceType::U, LinuxDeviceType::P] {
            let rule = LinuxDeviceCgroupBuilder::default()
                .typ(typ)
                .allow(true)
                .access("rwm")
                .build()
                .unwrap();
            let err = try_apply(&resources(vec![rule]), 245).unwrap_err();

            assert!(
                matches!(err, SystemdDevicesError::UnsupportedDeviceType(_)),
                "expected UnsupportedDeviceType for {typ:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn test_major_only_old_systemd_uses_device_group() {
        let proc_devices = proc_devices_fixture(PROC_DEVICES_SAMPLE);
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .major(1_i64)
            .allow(true)
            .access("r")
            .build()
            .unwrap();
        let props = try_apply_from(
            proc_devices.path().to_str().unwrap(),
            &resources(vec![rule]),
            239,
        )
        .unwrap();

        let allow = get_allow(&props);
        assert!(
            allow.contains(&entry("char-mem", "r")),
            "expected char-mem r in allow list, got {allow:?}"
        );
    }

    #[test]
    fn test_major_only_old_systemd_skips_unknown_group() {
        // A major /proc/devices does not list has no name to send, so the rule is dropped
        // rather than widened.
        let proc_devices = proc_devices_fixture(PROC_DEVICES_SAMPLE);
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .major(99_i64)
            .allow(true)
            .access("r")
            .build()
            .unwrap();
        let path = proc_devices.path().to_str().unwrap();
        let props = try_apply_from(path, &resources(vec![rule]), 239).unwrap();
        let without_the_rule = try_apply_from(path, &resources(vec![]), 239).unwrap();

        assert_eq!(
            get_allow(&props),
            get_allow(&without_the_rule),
            "the rule for the unknown major should contribute nothing"
        );
    }

    #[test]
    fn test_unreadable_proc_devices_is_reported() {
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .major(1_i64)
            .allow(true)
            .access("r")
            .build()
            .unwrap();
        let err = try_apply_from("/definitely/not/here", &resources(vec![rule]), 239).unwrap_err();

        assert!(
            matches!(err, SystemdDevicesError::ProcDevices { .. }),
            "expected ProcDevices, got {err:?}"
        );
    }

    #[test]
    fn test_missing_device_node_is_skipped_on_old_systemd() {
        // Before 240 systemd stat(2)s the path, so an entry for a node that is not there
        // would only earn a warning from systemd.
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::B)
            .major(9999_i64)
            .minor(9999_i64)
            .allow(true)
            .access("rw")
            .build()
            .unwrap();
        let proc_devices = proc_devices_fixture(PROC_DEVICES_SAMPLE);
        let props = try_apply_from(
            proc_devices.path().to_str().unwrap(),
            &resources(vec![rule.clone()]),
            239,
        )
        .unwrap();

        let allow = get_allow(&props);
        assert!(
            !allow.contains(&entry("/dev/block/9999:9999", "rw")),
            "expected the missing node to be left out, got {allow:?}"
        );

        // systemd 240 and later parse the numbers off the path, so it is sent as is.
        let props = apply(&resources(vec![rule]), 245);
        assert!(
            get_allow(&props).contains(&entry("/dev/block/9999:9999", "rw")),
            "expected the node to be sent on systemd 240+"
        );
    }

    #[test]
    fn test_deny_rule_falls_back_to_deny_all() {
        // Skipping the deny rule would grant the write the spec takes away again, because
        // the default rules allow /dev/null.
        let allow_null = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .major(1_i64)
            .minor(3_i64)
            .allow(true)
            .access("rwm")
            .build()
            .unwrap();
        let deny_write = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .major(1_i64)
            .minor(3_i64)
            .allow(false)
            .access("w")
            .build()
            .unwrap();
        let props = apply(&resources(vec![allow_null, deny_write]), 245);

        assert_eq!(get_policy(&props).as_deref(), Some("strict"));
        assert!(
            get_allow(&props).is_empty(),
            "expected an empty allow list, got {:?}",
            get_allow(&props)
        );
    }

    #[test]
    fn test_rule_without_access_is_left_out() {
        // systemd reads an entry with no access as "rwm", so it must not be sent at all.
        let rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::B)
            .major(8_i64)
            .minor(0_i64)
            .allow(true)
            .access("")
            .build()
            .unwrap();
        let props = apply(&resources(vec![rule]), 245);

        let allow = get_allow(&props);
        assert!(
            !allow.iter().any(|e| *e == entry("/dev/block/8:0", "")),
            "an entry without access must not be sent, got {allow:?}"
        );
    }

    #[test]
    fn test_find_device_group_char_is_prefixed() {
        // systemd needs "char-mem", not the bare "mem" from /proc/devices.
        assert_eq!(
            find_device_group_in(PROC_DEVICES_SAMPLE, LinuxDeviceType::C, 1),
            Some("char-mem".to_string())
        );
        assert_eq!(
            find_device_group_in(PROC_DEVICES_SAMPLE, LinuxDeviceType::C, 136),
            Some("char-pts".to_string())
        );
    }

    #[test]
    fn test_find_device_group_block_is_prefixed() {
        assert_eq!(
            find_device_group_in(PROC_DEVICES_SAMPLE, LinuxDeviceType::B, 8),
            Some("block-sd".to_string())
        );
    }

    #[test]
    fn test_find_device_group_does_not_cross_sections() {
        // Major 1 is a character device in the sample, so it must not match as a block one.
        assert_eq!(
            find_device_group_in(PROC_DEVICES_SAMPLE, LinuxDeviceType::B, 1),
            None
        );
    }

    #[test]
    fn test_find_device_group_skips_path_names() {
        // Major 4 is listed as both "/dev/vc/0" and "tty"; only the latter is a group name.
        assert_eq!(
            find_device_group_in(PROC_DEVICES_SAMPLE, LinuxDeviceType::C, 4),
            Some("char-tty".to_string())
        );
    }

    #[test]
    fn test_find_device_group_unknown_major_and_type() {
        assert_eq!(
            find_device_group_in(PROC_DEVICES_SAMPLE, LinuxDeviceType::C, 99),
            None
        );
        assert_eq!(
            find_device_group_in(PROC_DEVICES_SAMPLE, LinuxDeviceType::A, 1),
            None
        );
    }
}
