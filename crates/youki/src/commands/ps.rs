use std::path::PathBuf;
use std::process::Command;

use anyhow::{Result, bail};
use libcgroups::common::CgroupManager;
use liboci_cli::Ps;

use crate::commands::create_cgroup_manager;

pub fn ps(args: Ps, root_path: PathBuf) -> Result<()> {
    let cmanager = create_cgroup_manager(root_path, &args.container_id)?;

    let pids: Vec<i32> = cmanager
        .get_all_pids()?
        .iter()
        .map(|pid| pid.as_raw())
        .collect();

    if args.format == "json" {
        println!("{}", serde_json::to_string(&pids)?);
    } else if args.format == "table" {
        let default_ps_options = vec![String::from("-ef")];
        let ps_options = if args.ps_options.is_empty() {
            &default_ps_options
        } else {
            &args.ps_options
        };
        let output = Command::new("ps").args(ps_options).output()?;
        if !output.status.success() {
            println!("{}", std::str::from_utf8(&output.stderr)?);
        } else {
            let lines = std::str::from_utf8(&output.stdout)?;
            let lines: Vec<&str> = lines.split('\n').collect();
            let pid_index = get_pid_index(lines[0])?;
            println!("{}", &lines[0]);
            for line in &lines[1..] {
                if line.is_empty() {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                let pid: i32 = fields[pid_index].parse()?;
                if pids.contains(&pid) {
                    println!("{line}");
                }
            }
        }
    }
    Ok(())
}

fn get_pid_index(title: &str) -> Result<usize> {
    let titles = title.split_whitespace();

    for (index, name) in titles.enumerate() {
        if name == "PID" {
            return Ok(index);
        }
    }
    bail!("could't find PID field in ps output");
}
