use nix::sched::{CpuSet, sched_getaffinity, sched_setaffinity};
use nix::unistd::Pid;
use tracing::{Level, enabled};

#[derive(Debug, thiserror::Error)]
pub enum CPUAffinityError {
    #[error("invalid CPU string: {0}")]
    ParseError(String),
    #[error("values larger than {max} are not supported")]
    CpuOutOfRange { cpu: usize, max: usize },
    #[error("failed to set CPU for CPU {cpu}: {source}")]
    CpuSet {
        cpu: usize,
        #[source]
        source: nix::Error,
    },
    #[error("failed to setaffinity")]
    SetAffinity(#[source] nix::Error),
    #[error("failed to getaffinity")]
    GetAffinity(#[source] nix::Error),
}

type Result<T> = std::result::Result<T, CPUAffinityError>;

pub fn to_cpuset(cpuset_str: &str) -> Result<CpuSet> {
    let mut cpuset = CpuSet::new();
    let max_cpu = CpuSet::count();

    for part in cpuset_str
        .trim()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match part.split_once('-') {
            Some((start_str, end_str)) => {
                let start = parse_cpu_index(start_str, max_cpu)?;
                let end = parse_cpu_index(end_str, max_cpu)?;
                if start > end {
                    return Err(CPUAffinityError::ParseError(format!(
                        "invalid range: {}-{}",
                        start, end
                    )));
                }
                for cpu in start..=end {
                    cpuset
                        .set(cpu)
                        .map_err(|e| CPUAffinityError::CpuSet { cpu, source: e })?;
                }
            }
            None => {
                let cpu = parse_cpu_index(part, max_cpu)?;
                cpuset
                    .set(cpu)
                    .map_err(|e| CPUAffinityError::CpuSet { cpu, source: e })?;
            }
        }
    }
    Ok(cpuset)
}

fn parse_cpu_index(s: &str, max_cpu: usize) -> Result<usize> {
    let cpu: usize = s
        .parse()
        .map_err(|_| CPUAffinityError::ParseError(s.to_string()))?;
    if cpu >= max_cpu {
        return Err(CPUAffinityError::CpuOutOfRange {
            cpu,
            max: max_cpu - 1,
        });
    }
    Ok(cpu)
}

pub fn set_cpuset_affinity_from_string(pid: Pid, cpuset_str: &str) -> Result<()> {
    tracing::debug!(?cpuset_str, "setting CPU affinity for tenant container");
    sched_setaffinity(pid, &to_cpuset(cpuset_str)?).map_err(CPUAffinityError::SetAffinity)
}

// Logs a compact CPU affinity bitmask similar to runc's nsexec.c (see: https://github.com/opencontainers/runc/blob/main/libcontainer/nsenter/nsexec.c#L676).
// This helps in debugging which CPUs the current process is allowed to run on.
// Only logs when DEBUG level is enabled.
pub fn log_cpu_affinity() -> Result<()> {
    if !enabled!(Level::DEBUG) {
        return Ok(());
    }
    let cpuset = sched_getaffinity(Pid::this()).map_err(CPUAffinityError::GetAffinity)?;
    let mask = (0..usize::BITS as usize)
        .filter(|&i| cpuset.is_set(i).unwrap_or(false))
        .fold(0usize, |mask, i| mask | (1usize << i));
    tracing::debug!("affinity: 0x{:x}", mask);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_cpuset_single_values() {
        let cpuset = to_cpuset("0,1,2").unwrap();
        for cpu in [0, 1, 2] {
            assert!(cpuset.is_set(cpu).unwrap());
        }
    }

    #[test]
    fn test_to_cpuset_range() {
        let cpuset = to_cpuset("3-5").unwrap();
        for cpu in [3, 4, 5] {
            assert!(cpuset.is_set(cpu).unwrap());
        }
    }

    #[test]
    fn test_to_cpuset_mixed() {
        let cpuset = to_cpuset("0, 2-4, 6").unwrap();
        for cpu in [0, 2, 3, 4, 6] {
            assert!(cpuset.is_set(cpu).unwrap());
        }
        for cpu in [1, 5, 7] {
            assert!(!cpuset.is_set(cpu).unwrap_or(false));
        }
    }

    #[test]
    fn test_to_cpuset_spaces_and_empty() {
        let cpuset = to_cpuset("  , 1 , 3 , 5-7 , ").unwrap();
        for cpu in [1, 3, 5, 6, 7] {
            assert!(cpuset.is_set(cpu).unwrap());
        }
    }

    #[test]
    fn test_to_cpuset_invalid_range() {
        let err = to_cpuset("5-3").unwrap_err();
        matches!(err, CPUAffinityError::ParseError(_));
    }

    #[test]
    fn test_to_cpuset_invalid_value() {
        let err = to_cpuset("a,b,c").unwrap_err();
        matches!(err, CPUAffinityError::ParseError(_));
    }

    #[test]
    fn test_to_cpuset_max_allowed_cpu() {
        let max = CpuSet::count();
        let highest = max - 1;
        let cpuset = to_cpuset(&highest.to_string()).unwrap();
        assert!(cpuset.is_set(highest).unwrap());
    }

    #[test]
    fn test_to_cpuset_exceeds_max_cpu() {
        let max = CpuSet::count();
        let result = to_cpuset(&max.to_string());
        assert!(matches!(
            result,
            Err(CPUAffinityError::CpuOutOfRange { .. })
        ));
    }
}
