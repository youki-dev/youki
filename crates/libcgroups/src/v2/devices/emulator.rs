use oci_spec::runtime::{LinuxDeviceCgroup, LinuxDeviceType};

use crate::common::{default_allow_devices, default_devices};

// For cgroup v1 compatibility, runc implements a device emulator to calculate the final rules given
// a list of user-defined rules.
// https://github.com/opencontainers/runc/commit/2353ffec2bb670a200009dc7a54a56b93145f141
//
// I chose to implement a very simple algorithm, which will just work in most cases, but with
// diversion from cgroupv1 in some cases:
//  1. just add used-defined rules one by one
//  2. discard existing rules when encountering a rule with type='a', and change to deny/allow all
//     list according the 'allow' of the rule
//  3. bpf program will check rule one by one in *reversed* order, return action of first rule
//     which matches device access operation
//

// FIXME: should we use runc's implementation?
pub struct Emulator {
    pub default_allow: bool,
    pub rules: Vec<LinuxDeviceCgroup>,
}

impl Emulator {
    pub fn with_default_allow(default_allow: bool) -> Self {
        Emulator {
            default_allow,
            rules: Vec::new(),
        }
    }

    /// Deny by default, then the spec's rules in order, then the default devices. Shared by
    /// the cgroupfs v2 and systemd device controllers.
    pub fn from_spec(devices: &[LinuxDeviceCgroup]) -> Self {
        // FIXME: should we start as "deny all"?
        let mut emulator = Self::with_default_allow(false);

        // FIXME: apply user-defined and default rules in which order?
        for d in devices {
            tracing::debug!("apply user defined rule: {:?}", d);
            emulator.add_rule(d);
        }

        for d in default_devices()
            .iter()
            .map(LinuxDeviceCgroup::from)
            .chain(default_allow_devices())
        {
            tracing::debug!("apply default rule: {:?}", d);
            emulator.add_rule(&d);
        }

        emulator
    }

    pub fn add_rules(&mut self, rules: &[LinuxDeviceCgroup]) {
        for rule in rules {
            self.add_rule(rule);
        }
    }

    pub fn add_rule(&mut self, rule: &LinuxDeviceCgroup) {
        // special case, switch to blacklist or whitelist and clear all existing rules
        // NOTE: we ignore other fields when type='a', this is same as cgroup v1 and runc
        if rule.typ().unwrap_or_default() == LinuxDeviceType::A {
            self.default_allow = rule.allow();
            self.rules.clear();
            return;
        }

        // empty access match nothing, just discard this rule
        if rule.access().is_none() {
            return;
        }

        self.rules.push(rule.clone());
    }
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::LinuxDeviceCgroupBuilder;

    use super::*;

    #[test]
    fn test_with_default_allow() {
        // act
        let emulator = Emulator::with_default_allow(true);

        // assert
        assert_eq!(emulator.rules.len(), 0);
        assert!(emulator.default_allow);
    }

    #[test]
    fn test_type_a_rule() {
        // arrange
        let mut emulator = Emulator::with_default_allow(false);
        let cgroup = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .build()
            .unwrap();

        // act
        emulator.add_rule(&cgroup);

        // assert
        assert_eq!(emulator.rules.len(), 0);
        assert!(!emulator.default_allow);
    }

    #[test]
    fn test_add_empty_rule() {
        // arrange
        let mut emulator = Emulator::with_default_allow(false);
        let cgroup = LinuxDeviceCgroupBuilder::default().build().unwrap();

        // act
        emulator.add_rule(&cgroup);

        // assert
        assert_eq!(emulator.rules.len(), 0);
        assert!(!emulator.default_allow);
    }

    #[test]
    fn test_add_some_rule() {
        // arrange
        let mut emulator = Emulator::with_default_allow(false);
        let permission: &str = "PERMISSION";
        let cgroup = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::B)
            .access(permission)
            .build()
            .unwrap();

        // act
        emulator.add_rule(&cgroup);

        // assert
        let top_rule = emulator.rules.first().unwrap();
        assert_eq!(top_rule.access(), &Some(permission.to_string()));
        assert!(!emulator.default_allow);
    }

    #[test]
    fn test_from_spec_appends_default_rules_after_spec_rules() {
        // arrange
        let spec_rule = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::C)
            .allow(true)
            .major(10)
            .minor(200)
            .access("rw")
            .build()
            .unwrap();

        // act
        let emulator = Emulator::from_spec(std::slice::from_ref(&spec_rule));

        // assert
        let defaults: Vec<LinuxDeviceCgroup> = default_devices()
            .iter()
            .map(LinuxDeviceCgroup::from)
            .chain(default_allow_devices())
            .collect();
        assert!(!emulator.default_allow);
        assert_eq!(emulator.rules.len(), 1 + defaults.len());
        assert_eq!(emulator.rules[0], spec_rule);
        assert_eq!(emulator.rules[1..], defaults[..]);
    }

    #[test]
    fn test_from_spec_default_rules_keep_allow_all() {
        // The default rules are all allow rules, so adding them never turns an allow-all
        // spec into a restricted one and never adds a deny rule.
        let allow_all = LinuxDeviceCgroupBuilder::default()
            .typ(LinuxDeviceType::A)
            .allow(true)
            .build()
            .unwrap();

        let emulator = Emulator::from_spec(&[allow_all]);

        assert!(emulator.default_allow);
        assert!(emulator.rules.iter().all(|rule| rule.allow()));
    }
}
