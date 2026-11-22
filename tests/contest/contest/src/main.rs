use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use contest::logger;
use contest::tests::cgroups;
use contest::utils::support::{set_runtime_path, set_runtimetest_path};
use test_framework::TestManager;

#[derive(Parser, Debug)]
#[command(version = "0.0.1", author = "youki team")]
struct Opts {
    /// Enables debug output
    #[arg(short, long)]
    debug: bool,

    #[command(subcommand)]
    command: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// run the integration tests
    Run(Run),
    /// list available integration tests
    List,
}

#[derive(Parser, Debug)]
struct Run {
    /// Path for the container runtime to be tested
    #[arg(long)]
    runtime: PathBuf,
    /// Path for the runtimetest binary, which will be used to run tests inside the container
    #[arg(long)]
    runtimetest: PathBuf,
    /// Selected tests to be run, format should be
    /// space separated groups, eg
    /// -t group1::test1,test3 group2 group3::test5
    #[arg(short, long, num_args(1..), value_delimiter = ' ')]
    tests: Option<Vec<String>>,
}

// parse test string given in commandline option as pair of testgroup name and tests belonging to that
fn parse_tests(tests: &[String]) -> Vec<(&str, Option<Vec<&str>>)> {
    let mut ret = Vec::with_capacity(tests.len());
    for test in tests {
        if test.contains("::") {
            let (mod_name, test_names) = test.split_once("::").unwrap();
            let _tests = test_names.split(',').collect();
            ret.push((mod_name, Some(_tests)));
        } else {
            ret.push((test, None));
        }
    }
    ret
}

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    if let Err(e) = logger::init(opts.debug) {
        eprintln!("logger could not be initialized: {e:?}");
    }

    ////////// ANCHOR: register_test_groups
    let mut tm = TestManager::new();
    tm.add_registered_test_groups();
    ////////// ANCHOR_END: register_test_groups

    tm.add_cleanup(Box::new(cgroups::cleanup_v2));

    match opts.command {
        SubCommand::Run(args) => run(args, &tm).context("run tests")?,
        SubCommand::List => list(&tm).context("list tests")?,
    }

    Ok(())
}

fn get_abs_path(rel_path: &Path) -> PathBuf {
    match std::fs::canonicalize(rel_path) {
        // path is relative or resolved correctly
        Ok(path) => path,
        // path is name of program which probably exists in $PATH
        Err(_) => match which::which(rel_path) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Error in finding path {rel_path:?} : {e}\nexiting.");
                std::process::exit(66);
            }
        },
    }
}

fn run(opts: Run, test_manager: &TestManager) -> Result<()> {
    let runtime_path = get_abs_path(&opts.runtime);
    set_runtime_path(&runtime_path);

    let runtimetest_path = get_abs_path(&opts.runtimetest);
    set_runtimetest_path(&runtimetest_path);

    if let Some(tests) = opts.tests {
        let tests_to_run = parse_tests(&tests);
        test_manager.run_selected(tests_to_run);
    } else {
        test_manager.run_all();
    }

    Ok(())
}

fn list(test_manager: &TestManager) -> Result<()> {
    for test_group in test_manager.tests_groups() {
        println!("{test_group}");
    }

    Ok(())
}
