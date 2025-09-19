use std::error::Error;

use libcontainer::oci_spec::runtime::Spec;
use libcontainer::workload::{EMPTY, Executor, ExecutorError, ExecutorValidationError};
use wasmer::{Instance, Module, Store};
use wasmer_wasix::{WasiEnv, WasiError};

const EXECUTOR_NAME: &str = "wasmer";

#[derive(Clone)]
pub struct WasmerExecutor {}

impl Executor for WasmerExecutor {
    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        if !can_handle(spec) {
            return Err(ExecutorError::CantHandle(EXECUTOR_NAME));
        }

        tracing::debug!("executing workload with wasmer handler");
        let process = spec.process().as_ref();

        let args = process.and_then(|p| p.args().as_ref()).unwrap_or(&EMPTY);
        let env = process
            .and_then(|p| p.env().as_ref())
            .unwrap_or(&EMPTY)
            .iter()
            .filter_map(|e| {
                e.split_once('=')
                    .filter(|kv| !kv.0.contains('\u{0}') && !kv.1.contains('\u{0}'))
                    .map(|kv| (kv.0.trim(), kv.1.trim()))
            });

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

        let mut store = Store::default();
        let module = Module::from_file(&store, &args[0]).map_err(|err| {
            tracing::error!(err = ?err, file = ?args[0], "could not load wasm module from file");
            ExecutorError::Other("could not load wasm module from file".to_string())
        })?;

        let mut wasi_env = WasiEnv::builder("youki_wasm_app")
            .args(args.iter().skip(1))
            .envs(env)
            .finalize(&mut store)
            .map_err(|err| ExecutorError::Other(format!("could not create wasi env: {}", err)))?;

        let imports = wasi_env.import_object(&mut store, &module).map_err(|err| {
            ExecutorError::Other(format!("could not retrieve wasm imports: {}", err))
        })?;
        let instance = Instance::new(&mut store, &module, &imports).map_err(|err| {
            ExecutorError::Other(format!("could not instantiate wasm module: {}", err))
        })?;

        wasi_env
            .initialize(&mut store, instance.clone())
            .map_err(|err| {
                ExecutorError::Other(format!("could not initialize wasi env: {}", err))
            })?;

        let start = instance.exports.get_function("_start").map_err(|err| {
            ExecutorError::Other(format!(
                "could not retrieve wasm module main function: {err}"
            ))
        })?;

        start.call(&mut store, &[]).map_err(|err| {
            if let Some(WasiError::Exit(exit_code)) = err
                .source()
                .and_then(|err_source| err_source.downcast_ref::<WasiError>())
            {
                std::process::exit(exit_code.raw())
            } else {
                ExecutorError::Execution(err.into())
            }
        })?;

        wasi_env.cleanup(&mut store, None);

        std::process::exit(0)
    }

    fn validate(&self, spec: &Spec) -> Result<(), ExecutorValidationError> {
        if !can_handle(spec) {
            return Err(ExecutorValidationError::CantHandle(EXECUTOR_NAME));
        }

        Ok(())
    }
}

pub fn get_executor() -> WasmerExecutor {
    WasmerExecutor {}
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anyhow::{Context, Result};
    use libcontainer::oci_spec::runtime::SpecBuilder;

    use super::*;

    #[test]
    fn test_can_handle_oci_handler() -> Result<()> {
        let mut annotations = HashMap::with_capacity(1);
        annotations.insert("run.oci.handler".to_owned(), "wasm".to_owned());
        let spec = SpecBuilder::default()
            .annotations(annotations)
            .build()
            .context("build spec")?;

        assert!(can_handle(&spec));

        Ok(())
    }

    #[test]
    fn test_can_handle_compat_wasm_spec() -> Result<()> {
        let mut annotations = HashMap::with_capacity(1);
        annotations.insert("module.wasm.image/variant".to_owned(), "compat".to_owned());
        let spec = SpecBuilder::default()
            .annotations(annotations)
            .build()
            .context("build spec")?;

        assert!(can_handle(&spec));

        Ok(())
    }

    #[test]
    fn test_can_handle_no_execute() -> Result<()> {
        let spec = SpecBuilder::default().build().context("build spec")?;

        assert!(!can_handle(&spec));

        Ok(())
    }
}
