use libcontainer::oci_spec::runtime::Spec;
use libcontainer::workload::{EMPTY, Executor, ExecutorError, ExecutorValidationError};
use wasi_common::I32Exit;
use wasi_common::sync::{WasiCtxBuilder, add_to_linker};
use wasmtime::{Engine, Linker, Module, Store};

const EXECUTOR_NAME: &str = "wasmtime";

#[derive(Clone)]
pub struct WasmtimeExecutor {}

impl Executor for WasmtimeExecutor {
    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        if !can_handle(spec) {
            return Err(ExecutorError::CantHandle(EXECUTOR_NAME));
        }

        tracing::debug!("executing workload with wasmtime handler");
        let process = spec.process().as_ref();

        let args = spec
            .process()
            .as_ref()
            .and_then(|p| p.args().as_ref())
            .unwrap_or(&EMPTY);
        if args.is_empty() {
            tracing::error!("at least one process arg must be specified");
            return Err(ExecutorError::InvalidArg);
        }

        if !args[0].ends_with(".wasm") && !args[0].ends_with(".wat") {
            tracing::error!(
                "first argument must be a wasm or wat module, but was {}",
                args[0]
            );
            return Err(ExecutorError::InvalidArg);
        }

        let mut cmd = args[0].clone();
        let stripped = args[0].strip_prefix(std::path::MAIN_SEPARATOR);
        if let Some(cmd_stripped) = stripped {
            cmd = cmd_stripped.to_string();
        }

        let envs: Vec<(String, String)> = process
            .and_then(|p| p.env().as_ref())
            .unwrap_or(&EMPTY)
            .iter()
            .filter_map(|e| {
                e.split_once('=')
                    .map(|kv| (kv.0.trim().to_string(), kv.1.trim().to_string()))
            })
            .collect();

        let engine = Engine::default();
        let module = Module::from_file(&engine, &cmd).map_err(|err| {
            tracing::error!(err = ?err, file = ?cmd, "could not load wasm module from file");
            ExecutorError::Other("could not load wasm module from file".to_string())
        })?;

        let mut linker = Linker::new(&engine);
        add_to_linker(&mut linker, |s| s).map_err(|err| {
            tracing::error!(err = ?err, "cannot add wasi context to linker");
            ExecutorError::Other("cannot add wasi context to linker".to_string())
        })?;

        let wasi = WasiCtxBuilder::new()
            .inherit_stdio()
            .args(args)
            .map_err(|err| {
                ExecutorError::Other(format!("cannot add args to wasi context: {}", err))
            })?
            .envs(&envs)
            .map_err(|err| {
                ExecutorError::Other(format!("cannot add envs to wasi context: {}", err))
            })?
            .build();

        let mut store = Store::new(&engine, wasi);

        let instance = linker.instantiate(&mut store, &module).map_err(|err| {
            tracing::error!(err = ?err, "wasm module could not be instantiated");
            ExecutorError::Other("wasm module could not be instantiated".to_string())
        })?;
        let start = instance.get_func(&mut store, "_start").ok_or_else(|| {
            ExecutorError::Other("could not retrieve wasm module main function".into())
        })?;

        start.call(&mut store, &[], &mut []).map_err(|err| {
            match err.downcast_ref::<I32Exit>() {
                Some(exit) => std::process::exit(exit.0),
                None => ExecutorError::Execution(err.into()),
            }
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

pub fn get_executor() -> WasmtimeExecutor {
    WasmtimeExecutor {}
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
