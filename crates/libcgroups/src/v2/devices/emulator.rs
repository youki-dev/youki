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

    /// Builds the emulator for a container's `linux.resources.devices`: deny everything,
    /// then the spec's rules in order, then the default devices (`/dev/null`, `/dev/zero`,
    /// `/dev/tty`, ...).
    ///
    /// Both the cgroupfs v2 driver (eBPF program) and the systemd driver
    /// (`DevicePolicy`/`DeviceAllow`) start from this, so they enforce the same rules.
    /// The default devices are all allow rules for char or block devices, so adding them
    /// never changes `default_allow` and never adds a deny rule.
    pub fn from_spec(devices: &[LinuxDeviceCgroup]) -> Self {
        // FIXME: should we start as "deny all"?
        let mut emulator = Emulator::with_default_allow(false);

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

    fn default_rules() -> Vec<LinuxDeviceCgroup> {
        default_devices()
            .iter()
            .map(LinuxDeviceCgroup::from)
            .chain(default_allow_devices())
            .collect()
    }

    fn rule(typ: LinuxDeviceType, allow: bool) -> LinuxDeviceCgroup {
        let mut builder = LinuxDeviceCgroupBuilder::default().typ(typ).allow(allow);
        if typ != LinuxDeviceType::A {
            builder = builder.access("rw");
        }
        builder.build().unwrap()
    }

    #[test]
    fn test_from_spec_adds_spec_rules_then_default_devices() {
        // arrange
        let spec_rule = LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(LinuxDeviceType::C)
            .major(4)
            .minor(5)
            .access("rw")
            .build()
            .unwrap();

        // act
        let emulator = Emulator::from_spec(std::slice::from_ref(&spec_rule));

        // assert
        assert!(!emulator.default_allow);
        assert_eq!(emulator.rules, [vec![spec_rule], default_rules()].concat());
    }

    #[test]
    fn test_from_spec_without_rules_allows_only_default_devices() {
        // act
        let emulator = Emulator::from_spec(&[]);

        // assert
        assert!(!emulator.default_allow);
        assert_eq!(emulator.rules, default_rules());
    }

    #[test]
    fn test_from_spec_default_devices_do_not_change_policy() {
        // The systemd driver picks DevicePolicy from `default_allow` and from whether a deny
        // rule is left, so adding the default devices must change neither.
        let specs = [
            vec![],
            vec![rule(LinuxDeviceType::A, true)],
            vec![rule(LinuxDeviceType::A, false)],
            vec![rule(LinuxDeviceType::C, true)],
            vec![rule(LinuxDeviceType::C, false)],
            vec![
                rule(LinuxDeviceType::A, true),
                rule(LinuxDeviceType::C, false),
            ],
            vec![
                rule(LinuxDeviceType::A, false),
                rule(LinuxDeviceType::B, false),
            ],
        ];

        for spec in specs {
            // arrange
            let mut spec_only = Emulator::with_default_allow(false);
            spec_only.add_rules(&spec);

            // act
            let emulator = Emulator::from_spec(&spec);

            // assert
            assert_eq!(
                emulator.default_allow, spec_only.default_allow,
                "default_allow changed for {spec:?}"
            );
            assert_eq!(
                emulator.rules.iter().any(|r| !r.allow()),
                spec_only.rules.iter().any(|r| !r.allow()),
                "deny rules changed for {spec:?}"
            );
        }
    }

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
}
