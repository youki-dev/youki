use crate::seccomp::{Seccomp, SeccompProgramPlan};
use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccomp, LinuxSeccompBuilder, LinuxSyscall, LinuxSyscallBuilder,
};

use std::fs;
use std::io;
use std::path::Path;

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
                LinuxSyscallBuilder::default()
                    .names(syscall.names().to_vec())
                    .action(syscall.action())
                    .args(args.to_vec())
                    .build()?
            } else {
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
    }
    Ok(())
}
