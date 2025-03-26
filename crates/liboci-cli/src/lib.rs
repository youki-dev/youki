use std::fmt::Debug;
use std::path::PathBuf;

use clap::Parser;

// Subcommands that are specified in https://github.com/opencontainers/runtime-tools/blob/master/docs/command-line-interface.md

mod create;
mod delete;
mod kill;
mod start;
mod state;

pub use create::Create;
pub use delete::Delete;
pub use kill::Kill;
pub use start::Start;
pub use state::State;

// Other common subcommands that aren't specified in the document
mod checkpoint;
mod events;
mod exec;
mod features;
mod list;
mod pause;
mod ps;
mod resume;
mod run;
mod spec;
mod update;

pub use checkpoint::Checkpoint;
pub use events::Events;
pub use exec::Exec;
pub use features::Features;
pub use list::List;
pub use pause::Pause;
pub use ps::Ps;
pub use resume::Resume;
pub use run::Run;
pub use spec::Spec;
pub use update::Update;

// Subcommands parsed by liboci-cli, based on the [OCI
// runtime-spec](https://github.com/opencontainers/runtime-spec/blob/master/runtime.md)
// and specifically the [OCI Command Line
// Interface](https://github.com/opencontainers/runtime-tools/blob/master/docs/command-line-interface.md)
#[derive(Parser, Debug)]
pub enum StandardCmd {
    Create(Create),
    Start(Start),
    State(State),
    Kill(Kill),
    Delete(Delete),
}

// Extra subcommands not documented in the OCI Command Line Interface,
// but found in
// [runc](https://github.com/opencontainers/runc/blob/master/man/runc.8.md)
// and other runtimes.
#[derive(Parser, Debug)]
pub enum CommonCmd {
    Checkpointt(Checkpoint),
    Events(Events),
    Exec(Exec),
    Features(Features),
    List(List),
    Pause(Pause),
    #[clap(allow_hyphen_values = true)]
    Ps(Ps),
    Resume(Resume),
    Run(Run),
    Update(Update),
    Spec(Spec),
}

// The OCI Command Line Interface document doesn't define any global
// flags, but these are commonly accepted by runtimes
#[derive(Parser, Debug)]
pub struct GlobalOpts {
    /// set the log file to write youki logs to (default is '/dev/stderr')
    #[clap(short, long, overrides_with("log"))]
    pub log: Option<PathBuf>,
    /// change log level to debug, but the `log-level` flag takes precedence
    #[clap(long)]
    pub debug: bool,
    /// set the log format ('text' (default), or 'json') (default: "text")
    #[clap(long)]
    pub log_format: Option<String>,
    /// root directory to store container state
    #[clap(short, long)]
    pub root: Option<PathBuf>,
    /// Enable systemd cgroup manager, rather then use the cgroupfs directly.
    #[clap(short, long)]
    pub systemd_cgroup: bool,
    /// Entirely disable cgroup manipulation (breaks some operations, e.g. pause)
    #[clap(short, long)]
    pub disable_cgroups: bool,
}
