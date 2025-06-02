use serde::Deserialize;
use std::fs;
use std::io;
use oci_spec::runtime::{Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompArgBuilder, LinuxSeccompBuilder, LinuxSeccompOperator, LinuxSyscall, LinuxSyscallBuilder};
use crate::seccomp::{InstructionData, Seccomp};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
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
pub struct Includes {
    caps: Option<Vec<String>>,
    arches: Option<Vec<String>>,
    min_kernel: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Excludes {
    caps: Option<Vec<String>>,
    arches: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
pub struct Syscall {
    names: Vec<String>,
    action: String,
    args: Option<Vec<Argument>>,
    includes: Option<Includes>,
    excludes: Option<Excludes>,
    errno_ret: Option<i32>,
    comment: Option<String>,
}

pub fn convert_operation(op_str :&str) -> Option<LinuxSeccompOperator>{
    match op_str  {
        "SCMP_CMP_EQ" => Some(LinuxSeccompOperator::ScmpCmpEq),
        "SCMP_CMP_NE" => Some(LinuxSeccompOperator::ScmpCmpNe),
        "SCMP_CMP_MASKED_EQ" => Some(LinuxSeccompOperator::ScmpCmpMaskedEq),
        _ => None,
    }
}

pub fn convert_argument(args: Vec<Argument>) -> Result<Vec<LinuxSeccompArg>, String> {
    let mut seccomp_args: Vec<LinuxSeccompArg> = vec![];
    for arg in args {
        let op = convert_operation(&arg.op)
            .ok_or_else(|| format!("Invalid operation: {}", arg.op))?;
        let seccomp_arg = LinuxSeccompArgBuilder::default()
            .index(arg.index as usize)
            .value(arg.value)
            .op(op)
            .build()
            .map_err(|e| format!("Failed to build LinuxSeccompArg: {}", e))?;
        seccomp_args.push(seccomp_arg);
    }
    Ok(seccomp_args)
}

pub fn convert_action(action_str :&str) -> Option<LinuxSeccompAction>{
    match action_str  {
        "SCMP_ACT_ALLOW" => Some(LinuxSeccompAction::ScmpActAllow),
        "SCMP_ACT_ERRNO" => Some(LinuxSeccompAction::ScmpActErrno),
        _ => None,
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SeccompData {
    default_action: String,
    default_errno_ret: i32,
    arch_map: Vec<ArchMap>,
    syscalls: Vec<Syscall>,
}

pub fn read_seccomp_testdata(file_path: &str) -> Result<SeccompData, io::Error> {
    let contents = fs::read_to_string(file_path)?;
    let config: SeccompData = serde_json::from_str(&contents)?;
    Ok(config)
}

pub fn generate_seccomp_instruction(file_path: &str) -> anyhow::Result<()> {

    let seccomp = read_seccomp_testdata(file_path)?;
    let mut cnt = 0;
    for syscall in seccomp.syscalls {
        let action = convert_action(&syscall.action).unwrap();

        let mut build_syscall :LinuxSyscall;
        if syscall.args.is_some() {
            build_syscall = LinuxSyscallBuilder::default()
                .names(syscall.names)
                .action(action)
                .args(convert_argument(syscall.args.unwrap()))
                .build()?;
        } else {
            build_syscall = LinuxSyscallBuilder::default()
                .names(syscall.names)
                .action(action)
                .build()?;
        }

        let spec_seccomp = LinuxSeccompBuilder::default()
            .architectures(vec![OciSpecArch::ScmpArchX86_64])
            .default_action(convert_action(&seccomp.default_action).unwrap())
            .default_errno_ret(seccomp.default_errno_ret as u32)
            .syscalls(vec![build_syscall])
            .build()?;

        let inst_data = InstructionData::from_linux_seccomp(&spec_seccomp)?;
        let mut seccomp = Seccomp::new();
        if !inst_data.flags.is_empty() {
            seccomp.set_flags(inst_data.flags.clone());
        }
        seccomp.filters = Vec::from(inst_data);

        println!("--- test case {}---", cnt);
        for filter in &seccomp.filters {
            println!("code: {:02x}, jt: {:02x}, jf: {:02x}, k: {:08x}", filter.code, filter.offset_jump_true, filter.offset_jump_false, filter.multiuse_field)
        }
        println!("--- test case {} end", cnt);
        cnt += 1;
    }
    Ok(())
}