use std::collections::HashMap;

use libcontainer::oci_spec::runtime::Spec;
use libcontainer::workload::{Executor, ExecutorError, ExecutorValidationError};
use wasmedge_sdk::error::{CoreError, CoreExecutionError, WasmEdgeError};
use wasmedge_sdk::wasi::WasiModule;
use wasmedge_sdk::{Module, Store, Vm, params};

const EXECUTOR_NAME: &str = "wasmedge";

#[derive(Clone)]
pub struct WasmedgeExecutor {}

impl Executor for WasmedgeExecutor {
    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        if !can_handle(spec) {
            return Err(ExecutorError::CantHandle(EXECUTOR_NAME));
        }

        tracing::debug!("executing workload with wasmedge handler");

        // parse wasi parameters
        let args = get_args(spec);
        let mut cmd = args[0].clone();
        if let Some(stripped) = args[0].strip_prefix(std::path::MAIN_SEPARATOR) {
            cmd = stripped.to_string();
        }
        let envs = env_to_wasi(spec);

        // initialize the wasi module with the parsed parameters
        let mut wasi_module = WasiModule::create(
            Some(args.iter().map(|s| s as &str).collect()),
            Some(envs.iter().map(|s| s as &str).collect()),
            None,
        )
        .map_err(|err| ExecutorError::Other(format!("failed to create wasi module: {:?}", err)))?;

        let mut instances = HashMap::new();
        instances.insert(wasi_module.name().to_string(), wasi_module.as_mut());

        // create a vm
        let mut vm = Vm::new(
            Store::new(None, instances)
                .map_err(|err| ExecutorError::Other(format!("failed to create store: {}", err)))?,
        );

        let module = Module::from_file(None, cmd).unwrap();
        vm.register_module(Some("main"), module).unwrap();

        vm.run_func(Some("main"), "_start", params!())
            .map_err(|err| match *err {
                // This case indicates that the wasm code panicked.
                WasmEdgeError::Core(CoreError::Execution(CoreExecutionError::Unreachable)) => {
                    std::process::exit(101)
                }
                _ => ExecutorError::Execution(err),
            })?;

        std::process::exit(0)
    }

    fn validate(&self, spec: &Spec) -> Result<(), ExecutorValidationError> {
        if !can_handle(spec) {
            return Err(ExecutorValidationError::CantHandle(EXECUTOR_NAME));
        }

        Ok(())
    }
}

pub fn get_executor() -> WasmedgeExecutor {
    WasmedgeExecutor {}
}

fn can_handle(spec: &Spec) -> bool {
    if let Some(annotations) = spec.annotations() {
        if let Some(handler) = annotations.get("run.oci.handler") {
            return handler == "wasm";
        }

        if let Some(variant) = annotations.get("module.wasm.image/variant") {
            return variant == "compat";
        }
    }

    false
}

fn get_args(spec: &Spec) -> &[String] {
    let p = match spec.process() {
        None => return &[],
        Some(p) => p,
    };

    match p.args() {
        None => &[],
        Some(args) => args.as_slice(),
    }
}

fn env_to_wasi(spec: &Spec) -> Vec<String> {
    let default = vec![];
    // below we can be sure that process exists, as otherwise container init process
    // function would have returned error at the very start
    let env = spec
        .process()
        .as_ref()
        .unwrap()
        .env()
        .as_ref()
        .unwrap_or(&default);
    env.to_vec()
}
