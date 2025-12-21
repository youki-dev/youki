use crate::seccomp::{SeccompProgramPlan, Seccomp};
use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompArgBuilder,
    LinuxSeccompBuilder, LinuxSeccompOperator, LinuxSyscall, LinuxSyscallBuilder,
};
use serde::Deserialize;
use std::fs;
use std::io;
use std::path::Path;
use anyhow::{anyhow, Error};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ArchMap {
    architecture: String,
    sub_architectures: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Argument {
    index: i32,
    value: u64,
    op: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct Includes {
    caps: Option<Vec<String>>,
    arches: Option<Vec<String>>,
    min_kernel: Option<String>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct Excludes {
    caps: Option<Vec<String>>,
    arches: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct Syscall {
    names: Vec<String>,
    action: String,
    args: Option<Vec<Argument>>,
    includes: Option<Includes>,
    excludes: Option<Excludes>,
    errno_ret: Option<i32>,
    comment: Option<String>,
}

pub fn convert_operation(op_str: &str) -> Result<LinuxSeccompOperator, Error> {
    match op_str {
        "SCMP_CMP_EQ" => Ok(LinuxSeccompOperator::ScmpCmpEq),
        "SCMP_CMP_NE" => Ok(LinuxSeccompOperator::ScmpCmpNe),
        "SCMP_CMP_MASKED_EQ" => Ok(LinuxSeccompOperator::ScmpCmpMaskedEq),
        _ => Err(anyhow!("Cant match seccomp operator: {}", op_str)),
    }
}

pub fn convert_argument(args: Vec<Argument>) -> Result<Vec<LinuxSeccompArg>, Error> {
    let mut seccomp_args: Vec<LinuxSeccompArg> = vec![];
    for arg in args {
        let op =
            convert_operation(&arg.op)?;
        let seccomp_arg = LinuxSeccompArgBuilder::default()
            .index(arg.index as usize)
            .value(arg.value)
            .op(op)
            .build()?;
        seccomp_args.push(seccomp_arg);
    }
    Ok(seccomp_args)
}

pub fn convert_action(action_str: &str) -> Result<LinuxSeccompAction, Error> {
    match action_str {
        "SCMP_ACT_ALLOW" => Ok(LinuxSeccompAction::ScmpActAllow),
        "SCMP_ACT_ERRNO" => Ok(LinuxSeccompAction::ScmpActErrno),
        _ => Err(anyhow!("Cant match action: {}", action_str)),
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SeccompData {
    default_action: String,
    default_errno_ret: i32,
    arch_map: Vec<ArchMap>,
    syscalls: Vec<Syscall>,
}

pub fn read_seccomp_testdata(file_path: &Path) -> Result<SeccompData, io::Error> {
    let contents = fs::read_to_string(file_path)?;
    let config: SeccompData = serde_json::from_str(&contents)?;
    Ok(config)
}

pub fn generate_seccomp_instruction(file_path: &Path) -> anyhow::Result<()> {
    let seccomp = read_seccomp_testdata(file_path)?;
    let mut cnt = 0;
    #[allow(clippy::explicit_counter_loop)]
    for syscall in seccomp.syscalls {
        let action = convert_action(&syscall.action)?;

        let build_syscall: LinuxSyscall = if let Some(args) = syscall.args {
            LinuxSyscallBuilder::default()
                .names(syscall.names)
                .action(action)
                .args(convert_argument(args)?)
                .build()?
        } else {
            LinuxSyscallBuilder::default()
                .names(syscall.names)
                .action(action)
                .build()?
        };

        let spec_seccomp = LinuxSeccompBuilder::default()
            .architectures(vec![OciSpecArch::ScmpArchX86_64])
            .default_action(convert_action(&seccomp.default_action)?)
            .default_errno_ret(seccomp.default_errno_ret as u32)
            .syscalls(vec![build_syscall])
            .build()?;

        let inst_data = SeccompProgramPlan::from_linux_seccomp(&spec_seccomp)?;
        let mut seccomp = Seccomp::new();
        if !inst_data.flags.is_empty() {
            seccomp.set_flags(inst_data.flags.clone());
        }
        seccomp.filters = Vec::try_from(inst_data)?;
        println!("--- test case {}---", cnt);
        for filter in &seccomp.filters {
            println!(
                "code: {:02x}, jt: {:02x}, jf: {:02x}, k: {:08x}",
                filter.code,
                filter.offset_jump_true,
                filter.offset_jump_false,
                filter.multiuse_field
            )
        }
        println!("--- test case {} end", cnt);
        cnt += 1;
    }
    Ok(())
}
