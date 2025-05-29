use std::vec;

use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMapping, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceBuilder,
    LinuxNamespaceType, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec(uid_mappings: Vec<LinuxIdMapping>, gid_mappings: Vec<LinuxIdMapping>) -> Spec {
    let mut namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces();
    let userns = LinuxNamespaceBuilder::default()
        .typ(LinuxNamespaceType::User)
        .build()
        .unwrap();
    namespaces.push(userns);

    let linux_builder = LinuxBuilder::default()
        .namespaces(namespaces)
        .uid_mappings(uid_mappings)
        .gid_mappings(gid_mappings)
        .build()
        .expect("error in building linux config");

    SpecBuilder::default()
        .linux(linux_builder)
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "uid_mappings".to_string()])
                .build()
                .expect("error in creating process config"),
        )
        .build()
        .unwrap()
}

fn uid_mappings_test() -> TestResult {
    let uid_mappings = vec![LinuxIdMappingBuilder::default()
        .host_id(1000_u32)
        .container_id(0_u32)
        .size(2000_u32)
        .build()
        .unwrap()];

    let gid_mappings = vec![LinuxIdMappingBuilder::default()
        .host_id(1000_u32)
        .container_id(0_u32)
        .size(3000_u32)
        .build()
        .unwrap()];

    let spec = create_spec(uid_mappings, gid_mappings);
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_uid_mappings_test() -> TestGroup {
    let mut test_group = TestGroup::new("uid_mappings");
    let uid_mappings_test = Test::new("uid_mappings", Box::new(uid_mappings_test));

    test_group.add(vec![Box::new(uid_mappings_test)]);

    test_group
}
