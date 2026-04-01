use libseccomp::*;
use oci_spec::runtime::LinuxSeccompOperator;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[path = "./helpers/mod.rs"]
mod utils;

#[test]
fn read_json() -> anyhow::Result<()> {
    let mut cnt = 0;
    let seccomp = utils::read_seccomp_testdata("tests/fixtures/default_x86_64.json".as_ref())?;

    if let Some(seccomp_syscalls) = seccomp.syscalls() {
        for linux_syscall in seccomp_syscalls {
            let mut filter = ScmpFilterContext::new(
                utils::convert_action(seccomp.default_action(), seccomp.default_errno_ret()).unwrap(),
            )?;
            filter.add_arch(ScmpArch::Native)?;

            let action = utils::convert_action(linux_syscall.action(), linux_syscall.errno_ret())?;
            let mut has_args: bool = false; 
			for syscall in linux_syscall.names().iter() {
                let scmp_syscall = ScmpSyscall::from_name(syscall)?;
                if let Some(args) = linux_syscall.args() {
                    has_args = true;
                    if args[0].op() == LinuxSeccompOperator::ScmpCmpMaskedEq {
                        let cmp = ScmpArgCompare::new(
                            args[0].index() as u32,
                            utils::convert_operation(args[0].op(), Option::from(args[0].value()))?,
                            args[0].value(),
                        );
                        filter.add_rule_conditional(action, scmp_syscall, &[cmp])?;
                    } else {
                        let cmp = ScmpArgCompare::new(
                            args[0].index() as u32,
                            utils::convert_operation(args[0].op(), Some(0))?,
                            args[0].value(),
                        );
                        filter.add_rule_conditional(action, scmp_syscall, &[cmp])?;
                    }
                } else {
                    filter.add_rule(action, scmp_syscall)?;
                }
            }
            let tmpfile: File = tempfile::tempfile()?;
            let mut read_handle = tmpfile.try_clone()?;
            filter.export_bpf(tmpfile)?;
            read_handle.seek(SeekFrom::Start(0))?;

            let mut buffer = Vec::new();
            read_handle.read_to_end(&mut buffer)?;
			if has_args {
				println!("--- test case {} with args---", cnt);
			} else {
            	println!("--- test case {}---", cnt);
			}
            for chunk in buffer.chunks(8) {
                if chunk.len() == 8 {
                    let code = u16::from_le_bytes([chunk[0], chunk[1]]);
                    let jt = chunk[2];
                    let jf = chunk[3];
                    let k = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);

                    println!(
                        "code: {:02x}, jt: {:02x}, jf: {:02x}, k: {:08x}",
                        code, jt, jf, k
                    );
                }
            }
            println!("--- test case {} end", cnt);
            cnt += 1;
        }
    }

    Ok(())
}
