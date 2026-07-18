use anyhow::Result;

#[cfg(feature = "cgroupsv2_devices")]
mod bpf {
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    use anyhow::{Result, bail};
    use clap::{Arg, Command};
    use libcgroups::v2::devices::{bpf, emulator, program};
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;
    use oci_spec::runtime::LinuxDeviceCgroup;

    const LICENSE: &str = "Apache";
    fn cli() -> Command {
        clap::Command::new("bpf")
            .version("0.1")
            .about("tools to test BPF program for cgroups v2 devices")
            .arg(Arg::new("cgroup_dir").short('c').value_name("CGROUP_DIR"))
            .subcommand(
                Command::new("query").about("query list of BPF programs attached to cgroup dir"),
            )
            .subcommand(
                Command::new("detach")
                    .about("detach BPF program by id")
                    .arg(
                        Arg::new("id")
                            .value_name("PROG_ID")
                            .required(true)
                            .help("ID of BPF program returned by query command"),
                    ),
            )
            .subcommand(
                Command::new("attach")
                    .about("compile rules to BPF and attach to cgroup dir")
                    .arg(
                        Arg::new("input_file")
                            .value_name("INPUT_FILE")
                            .required(true)
                            .help("File contains Vec<LinuxDeviceCgroup> in json format"),
                    ),
            )
    }

    fn parse_cgroupv1_device_rules<P: AsRef<Path>>(path: P) -> Result<Vec<LinuxDeviceCgroup>> {
        let content = std::fs::read_to_string(path)?;
        let devices = serde_json::from_str(&content)?;
        Ok(devices)
    }

    pub fn run() -> Result<()> {
        let matches = cli().get_matches();
        let cgroup_dir = matches.get_one::<String>("cgroup_dir").unwrap();
        let cgroup_fd = nix::dir::Dir::open(
            cgroup_dir.as_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::from_bits(0o600).unwrap(),
        )?;
        match matches.subcommand() {
            Some(("query", _)) => {
                let progs = bpf::prog::query(cgroup_fd.as_raw_fd())?;
                for prog in &progs {
                    println!("prog: id={}, fd={}", prog.id, prog.fd);
                }
            }
            Some(("detach", submatch)) => {
                let prog_id = submatch.get_one::<String>("id").unwrap().parse::<u32>()?;
                let progs = bpf::prog::query(cgroup_fd.as_raw_fd())?;
                let prog = progs.iter().find(|v| v.id == prog_id);
                if prog.is_none() {
                    bail!("can't get prog fd by prog id");
                }

                bpf::prog::detach2(prog.unwrap().fd, cgroup_fd.as_raw_fd())?;
                println!("detach ok");
            }
            Some(("attach", submatch)) => {
                let input_file = submatch.get_one::<String>("input_file").unwrap();
                let rules = parse_cgroupv1_device_rules(input_file)?;
                let mut emulator = emulator::Emulator::with_default_allow(false);
                emulator.add_rules(&rules);
                let prog = program::Program::from_rules(&emulator.rules, emulator.default_allow)?;
                let prog_fd = bpf::prog::load(LICENSE, prog.bytecodes())?;
                bpf::prog::attach(prog_fd, cgroup_fd.as_raw_fd())?;
                println!("attach ok");
            }

            _ => unreachable!(),
        };
        Ok(())
    }
}

#[cfg(not(feature = "cgroupsv2_devices"))]
mod bpf {
    use anyhow::{Result, bail};

    pub fn run() -> Result<()> {
        if !cfg!(feature = "cgroupsv2_devices") {
            bail!("cgroupsv2_devices feature is not enabled");
        }

        unreachable!()
    }
}

fn main() -> Result<()> {
    env_logger::init();
    bpf::run()?;

    Ok(())
}
