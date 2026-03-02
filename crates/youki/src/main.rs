//! # Youki
//! Container Runtime written in Rust, inspired by [railcar](https://github.com/oracle/railcar)
//! This crate provides a container runtime which can be used by a high-level container runtime to run containers.
mod commands;
mod observability;
mod rootpath;
mod workload;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use libcontainer::syscall::syscall::create_syscall;
use liboci_cli::{CommonCmd, GlobalOpts, StandardCmd};

use crate::commands::info;

// Additional options that are not defined in OCI runtime-spec, but are used by Youki.
#[derive(Parser, Debug)]
struct YoukiExtendOpts {
    /// Enable logging to systemd-journald
    #[clap(long)]
    pub systemd_log: bool,
    /// set the log level (default is 'error')
    #[clap(long)]
    pub log_level: Option<String>,
}

// High-level commandline option definition
// This takes global options as well as individual commands as specified in [OCI runtime-spec](https://github.com/opencontainers/runtime-spec/blob/master/runtime.md)
// Also check [runc commandline documentation](https://github.com/opencontainers/runc/blob/master/man/runc.8.md) for more explanation
#[derive(Parser, Debug)]
#[clap(author = env!("CARGO_PKG_AUTHORS"))]
#[command(version, disable_version_flag = true)]
struct Opts {
    #[clap(flatten)]
    global: GlobalOpts,

    #[clap(flatten)]
    youki_extend: YoukiExtendOpts,

    #[clap(subcommand)]
    subcmd: Option<SubCommand>,

    /// Display youki version and commit hash
    #[clap(short, long)]
    version: bool,
}

// Subcommands accepted by Youki, confirming with [OCI runtime-spec](https://github.com/opencontainers/runtime-spec/blob/master/runtime.md)
// Also for a short information, check [runc commandline documentation](https://github.com/opencontainers/runc/blob/master/man/runc.8.md)
#[derive(Parser, Debug)]
enum SubCommand {
    // Standard and common commands handled by the liboci_cli crate
    #[clap(flatten)]
    Standard(Box<liboci_cli::StandardCmd>),
    #[clap(flatten)]
    Common(Box<liboci_cli::CommonCmd>),

    // Youki specific extensions
    Info(info::Info),
    Completion(commands::completion::Completion),
}

/// This is the entry point in the container runtime. The binary is run by a high-level container runtime,
/// with various flags passed. This parses the flags, creates and manages appropriate resources.
fn main() -> Result<()> {
    // A malicious container can gain access to the host machine by modifying youki's host
    // binary and infect it with malicious code. This vulnerability was first discovered
    // in runc and was assigned as CVE-2019-5736, but it also affects youki.
    //
    // The fix is to copy /proc/self/exe in an anonymous file descriptor (created via memfd_create),
    // seal it and re-execute it. Because the final step is re-execution, this needs to be done at
    // the beginning of this process.
    //
    // Ref: https://github.com/opencontainers/runc/commit/0a8e4117e7f715d5fbeef398405813ce8e88558b
    // Ref: https://github.com/lxc/lxc/commit/6400238d08cdf1ca20d49bafb85f4e224348bf9d
    pentacle::ensure_sealed().context("failed to seal /proc/self/exe")?;

    let opts = Opts::parse();
    if opts.version {
        info::print_youki();
        return Ok(());
    }

    let mut app = Opts::command();
    let syscall = create_syscall();

    observability::init(&opts).map_err(|err| {
        eprintln!("failed to initialize observability: {}", err);
        err
    })?;

    tracing::debug!(
        "started by user {} with {:?}",
        syscall.get_euid(),
        std::env::args_os()
    );

    let root_path = rootpath::determine(opts.global.root, &*syscall)?;
    let systemd_cgroup = opts.global.systemd_cgroup;

    let cmd_result = match opts.subcmd {
        Some(SubCommand::Standard(cmd)) => match *cmd {
            StandardCmd::Create(create) => {
                commands::create::create(create, root_path, systemd_cgroup)
            }
            StandardCmd::Start(start) => commands::start::start(start, root_path),
            StandardCmd::Kill(kill) => commands::kill::kill(kill, root_path),
            StandardCmd::Delete(delete) => commands::delete::delete(delete, root_path),
            StandardCmd::State(state) => commands::state::state(state, root_path),
        },
        Some(SubCommand::Common(cmd)) => match *cmd {
            CommonCmd::Checkpoint(checkpoint) => {
                commands::checkpoint::checkpoint(checkpoint, root_path)
            }
            CommonCmd::Events(events) => commands::events::events(events, root_path),
            CommonCmd::Exec(exec) => match commands::exec::exec(exec, root_path) {
                Ok(exit_code) => std::process::exit(exit_code),
                Err(e) => {
                    tracing::error!("error in executing command: {:?}", e);
                    eprintln!("exec failed : {e}");
                    std::process::exit(-1);
                }
            },
            CommonCmd::Features(features) => commands::features::features(features),
            CommonCmd::List(list) => commands::list::list(list, root_path),
            CommonCmd::Pause(pause) => commands::pause::pause(pause, root_path),
            CommonCmd::Ps(ps) => commands::ps::ps(ps, root_path),
            CommonCmd::Restore(restore) => {
                match commands::restore::restore(restore, root_path, systemd_cgroup) {
                    Ok(exit_code) => std::process::exit(exit_code),
                    Err(e) => {
                        tracing::error!("error in executing command: {:?}", e);
                        eprintln!("restore failed : {e}");
                        std::process::exit(-1);
                    }
                }
            }
            CommonCmd::Resume(resume) => commands::resume::resume(resume, root_path),
            CommonCmd::Run(run) => match commands::run::run(run, root_path, systemd_cgroup) {
                Ok(exit_code) => std::process::exit(exit_code),
                Err(e) => {
                    tracing::error!("error in executing command: {:?}", e);
                    eprintln!("run failed : {e}");
                    std::process::exit(-1);
                }
            },
            CommonCmd::Spec(spec) => commands::spec_json::spec(spec, &*syscall),
            CommonCmd::Update(update) => commands::update::update(update, root_path),
        },

        Some(SubCommand::Info(info)) => commands::info::info(info),
        Some(SubCommand::Completion(completion)) => {
            commands::completion::completion(completion, &mut app)
        }
        None => app
            .print_help()
            .map_err(|e| anyhow::anyhow!("failed to print help: {e}")),
    };

    if let Err(ref e) = cmd_result {
        tracing::error!("error in executing command: {:?}", e);
        eprintln!("error in executing command: {:?}", e);
    }
    cmd_result
}
