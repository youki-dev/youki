use std::vec;

use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMapping, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceBuilder,
    LinuxNamespaceType, ProcessBuilder, Spec, SpecBuilder,
};
use rand::RngExt;
use test_framework::{Test, TestGroup, TestResult};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

// The `host_id` is randomly chosen between 1000 and 2000, while the `size`
// is randomly chosen between 100 and 2500. The `container_id` is fixed at 0.
fn generate_random_id_mappings() -> Vec<LinuxIdMapping> {
    let mut rng = rand::rng();

    let host_id: u32 = rng.random_range(1000..=2000);
    let size: u32 = rng.random_range(100..=2500);

    // container_id 0 must exist, otherwise container creation will fail
    let id_mapping = LinuxIdMappingBuilder::default()
        .host_id(host_id)
        .container_id(0_u32)
        .size(size)
        .build()
        .expect("error in building LinuxIdMapping");

    vec![id_mapping]
}

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
    let uid_mappings = generate_random_id_mappings();
    let gid_mappings = generate_random_id_mappings();

    let spec = create_spec(uid_mappings, gid_mappings);
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_uid_mappings_test() -> TestGroup {
    let mut test_group = TestGroup::new("uid_mappings");
    let uid_mappings_test = Test::new("uid_mappings", Box::new(uid_mappings_test));

    test_group.add(vec![Box::new(uid_mappings_test)]);

    test_group
}
