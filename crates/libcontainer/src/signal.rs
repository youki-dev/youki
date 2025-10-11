//! Returns *nix signal enum value from passed string

use std::convert::TryFrom;

use nix::sys::signal::Signal as NixSignal;

/// POSIX Signal
#[derive(Debug)]
pub struct Signal(NixSignal);

#[derive(Debug, thiserror::Error)]
pub enum SignalError<T> {
    #[error("invalid signal: {0}")]
    InvalidSignal(T),
}

impl TryFrom<&str> for Signal {
    type Error = SignalError<String>;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        use NixSignal::*;

        Ok(Signal(match s.to_ascii_uppercase().as_str() {
            "1" | "HUP" | "SIGHUP" => SIGHUP,
            "2" | "INT" | "SIGINT" => SIGINT,
            "3" | "QUIT" | "SIGQUIT" => SIGQUIT,
            "4" | "ILL" | "SIGILL" => SIGILL,
            "5" | "BUS" | "SIGBUS" => SIGBUS,
            "6" | "ABRT" | "IOT" | "SIGABRT" | "SIGIOT" => SIGABRT,
            "7" | "TRAP" | "SIGTRAP" => SIGTRAP,
            "8" | "FPE" | "SIGFPE" => SIGFPE,
            "9" | "KILL" | "SIGKILL" => SIGKILL,
            "10" | "USR1" | "SIGUSR1" => SIGUSR1,
            "11" | "SEGV" | "SIGSEGV" => SIGSEGV,
            "12" | "USR2" | "SIGUSR2" => SIGUSR2,
            "13" | "PIPE" | "SIGPIPE" => SIGPIPE,
            "14" | "ALRM" | "SIGALRM" => SIGALRM,
            "15" | "TERM" | "SIGTERM" => SIGTERM,
            "16" | "STKFLT" | "SIGSTKFLT" => SIGSTKFLT,
            "17" | "CHLD" | "SIGCHLD" => SIGCHLD,
            "18" | "CONT" | "SIGCONT" => SIGCONT,
            "19" | "STOP" | "SIGSTOP" => SIGSTOP,
            "20" | "TSTP" | "SIGTSTP" => SIGTSTP,
            "21" | "TTIN" | "SIGTTIN" => SIGTTIN,
            "22" | "TTOU" | "SIGTTOU" => SIGTTOU,
            "23" | "URG" | "SIGURG" => SIGURG,
            "24" | "XCPU" | "SIGXCPU" => SIGXCPU,
            "25" | "XFSZ" | "SIGXFSZ" => SIGXFSZ,
            "26" | "VTALRM" | "SIGVTALRM" => SIGVTALRM,
            "27" | "PROF" | "SIGPROF" => SIGPROF,
            "28" | "WINCH" | "SIGWINCH" => SIGWINCH,
            "29" | "IO" | "SIGIO" => SIGIO,
            "30" | "PWR" | "SIGPWR" => SIGPWR,
            "31" | "SYS" | "SIGSYS" => SIGSYS,
            _ => return Err(SignalError::InvalidSignal(s.to_string())),
        }))
    }
}

impl TryFrom<i32> for Signal {
    type Error = SignalError<i32>;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        NixSignal::try_from(value)
            .map_err(|_| SignalError::InvalidSignal(value))
            .map(Signal)
    }
}

impl From<NixSignal> for Signal {
    fn from(s: NixSignal) -> Self {
        Signal(s)
    }
}

impl Signal {
    pub(crate) fn into_raw(self) -> NixSignal {
        self.0
    }

    pub(crate) fn exit_code(&self) -> i32 {
        128 + self.0 as i32
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nix::sys::signal::Signal::*;

    use super::*;

    #[test]
    fn test_conversion_from_string() {
        let mut test_sets = HashMap::new();
        test_sets.insert(SIGHUP, vec!["1", "HUP", "SIGHUP"]);
        test_sets.insert(SIGINT, vec!["2", "INT", "SIGINT"]);
        test_sets.insert(SIGQUIT, vec!["3", "QUIT", "SIGQUIT"]);
        test_sets.insert(SIGILL, vec!["4", "ILL", "SIGILL"]);
        test_sets.insert(SIGBUS, vec!["5", "BUS", "SIGBUS"]);
        test_sets.insert(SIGABRT, vec!["6", "ABRT", "IOT", "SIGABRT", "SIGIOT"]);
        test_sets.insert(SIGTRAP, vec!["7", "TRAP", "SIGTRAP"]);
        test_sets.insert(SIGFPE, vec!["8", "FPE", "SIGFPE"]);
        test_sets.insert(SIGKILL, vec!["9", "KILL", "SIGKILL"]);
        test_sets.insert(SIGUSR1, vec!["10", "USR1", "SIGUSR1"]);
        test_sets.insert(SIGSEGV, vec!["11", "SEGV", "SIGSEGV"]);
        test_sets.insert(SIGUSR2, vec!["12", "USR2", "SIGUSR2"]);
        test_sets.insert(SIGPIPE, vec!["13", "PIPE", "SIGPIPE"]);
        test_sets.insert(SIGALRM, vec!["14", "ALRM", "SIGALRM"]);
        test_sets.insert(SIGTERM, vec!["15", "TERM", "SIGTERM"]);
        test_sets.insert(SIGSTKFLT, vec!["16", "STKFLT", "SIGSTKFLT"]);
        test_sets.insert(SIGCHLD, vec!["17", "CHLD", "SIGCHLD"]);
        test_sets.insert(SIGCONT, vec!["18", "CONT", "SIGCONT"]);
        test_sets.insert(SIGSTOP, vec!["19", "STOP", "SIGSTOP"]);
        test_sets.insert(SIGTSTP, vec!["20", "TSTP", "SIGTSTP"]);
        test_sets.insert(SIGTTIN, vec!["21", "TTIN", "SIGTTIN"]);
        test_sets.insert(SIGTTOU, vec!["22", "TTOU", "SIGTTOU"]);
        test_sets.insert(SIGURG, vec!["23", "URG", "SIGURG"]);
        test_sets.insert(SIGXCPU, vec!["24", "XCPU", "SIGXCPU"]);
        test_sets.insert(SIGXFSZ, vec!["25", "XFSZ", "SIGXFSZ"]);
        test_sets.insert(SIGVTALRM, vec!["26", "VTALRM", "SIGVTALRM"]);
        test_sets.insert(SIGPROF, vec!["27", "PROF", "SIGPROF"]);
        test_sets.insert(SIGWINCH, vec!["28", "WINCH", "SIGWINCH"]);
        test_sets.insert(SIGIO, vec!["29", "IO", "SIGIO"]);
        test_sets.insert(SIGPWR, vec!["30", "PWR", "SIGPWR"]);
        test_sets.insert(SIGSYS, vec!["31", "SYS", "SIGSYS"]);
        for (signal, strings) in test_sets {
            for s in strings {
                assert_eq!(signal, Signal::try_from(s).unwrap().into_raw());
            }
        }
    }

    #[test]
    fn test_conversion_from_string_should_be_failed() {
        assert!(Signal::try_from("invalid").is_err())
    }
}
