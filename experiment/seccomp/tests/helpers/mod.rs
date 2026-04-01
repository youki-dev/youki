use oci_spec::runtime::{Arch as OciSpecArch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSeccompOperator, LinuxSyscall, LinuxSyscallBuilder};
use libseccomp::ScmpAction::{Allow, Errno, KillProcess, KillThread, Log, Notify, Trace, Trap};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::fs;
use std::io;
use std::path::Path;
use libseccomp::{ScmpAction, ScmpCompareOp};
use anyhow::Error;

pub fn convert_action(
    action: LinuxSeccompAction,
    option: Option<u32>,
) -> Result<ScmpAction, Error> {
    match action {
        LinuxSeccompAction::ScmpActKill => Ok(KillProcess),
        LinuxSeccompAction::ScmpActKillThread => Ok(KillThread),
        LinuxSeccompAction::ScmpActKillProcess => Ok(KillProcess),
        LinuxSeccompAction::ScmpActTrap => Ok(Trap),
        LinuxSeccompAction::ScmpActErrno => Ok(Errno(option.unwrap() as i32)),
        LinuxSeccompAction::ScmpActNotify => Ok(Notify),
        LinuxSeccompAction::ScmpActTrace => Ok(Trace(option.unwrap() as u16)),
        LinuxSeccompAction::ScmpActLog => Ok(Log),
        LinuxSeccompAction::ScmpActAllow => Ok(Allow),
    }
}

pub fn convert_operation(
    op: LinuxSeccompOperator,
    value: Option<u64>,
) -> Result<ScmpCompareOp, Error> {
    match op {
        LinuxSeccompOperator::ScmpCmpNe => Ok(ScmpCompareOp::NotEqual),
        LinuxSeccompOperator::ScmpCmpLt => Ok(ScmpCompareOp::Less),
        LinuxSeccompOperator::ScmpCmpLe => Ok(ScmpCompareOp::LessOrEqual),
        LinuxSeccompOperator::ScmpCmpEq => Ok(ScmpCompareOp::Equal),
        LinuxSeccompOperator::ScmpCmpGe => Ok(ScmpCompareOp::GreaterEqual),
        LinuxSeccompOperator::ScmpCmpGt => Ok(ScmpCompareOp::Greater),
        LinuxSeccompOperator::ScmpCmpMaskedEq => Ok(ScmpCompareOp::MaskedEqual(value.unwrap())),
    }
}
pub fn read_seccomp_testdata(file_path: &Path) -> Result<LinuxSeccomp, io::Error> {
    let contents = fs::read_to_string(file_path)?;
    let seccomp: LinuxSeccomp = serde_json::from_str(&contents)?;
    Ok(seccomp)
}

pub fn generate_seccomp_instruction(file_path: &Path) -> anyhow::Result<()> {
    let seccomp = read_seccomp_testdata(file_path)?;
    let mut cnt = 0;

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            let mut build_syscall: LinuxSyscall = if let Some(args) = syscall.args() {
                println!("--- test case {} with args---", cnt);
                LinuxSyscallBuilder::default()
                    .names(syscall.names().to_vec())
                    .action(syscall.action())
                    .args(args.to_vec())
                    .build()?
            } else {
                println!("--- test case {}---", cnt);
                LinuxSyscallBuilder::default()
                    .names(syscall.names().to_vec())
                    .action(syscall.action())
                    .build()?
            };
            if let Some(errno_ret) = syscall.errno_ret() {
                build_syscall.set_errno_ret(Option::from(errno_ret));
            }
            let spec_seccomp = LinuxSeccompBuilder::default()
                .architectures(vec![OciSpecArch::ScmpArchX86_64])
                .default_action(seccomp.default_action())
                .default_errno_ret(seccomp.default_errno_ret().unwrap())
                .syscalls(vec![build_syscall])
                .build()?;
            let inst_data = SeccompProgramPlan::try_from(spec_seccomp)?;
            let mut seccomp = Seccomp::new();
            if !inst_data.flags.is_empty() {
                seccomp.set_flags(inst_data.flags.clone());
            }
            seccomp.filters = Vec::try_from(inst_data)?;
            // println!("--- test case {}---", cnt);
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
    }
    Ok(())
}
