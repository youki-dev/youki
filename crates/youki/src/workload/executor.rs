use libcontainer::oci_spec::runtime::Spec;
use libcontainer::workload::{Executor, ExecutorError, ExecutorValidationError};

#[derive(Clone)]
pub struct DefaultExecutor {}

impl Executor for DefaultExecutor {
    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        #[cfg(feature = "wasm-wasmer")]
        match super::wasmer::get_executor().exec(spec) {
            Ok(_) => std::process::exit(0),
            Err(ExecutorError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }
        #[cfg(feature = "wasm-wasmedge")]
        match super::wasmedge::get_executor().exec(spec) {
            Ok(_) => std::process::exit(0),
            Err(ExecutorError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }
        #[cfg(feature = "wasm-wasmtime")]
        match super::wasmtime::get_executor().exec(spec) {
            Ok(_) => std::process::exit(0),
            Err(ExecutorError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }

        // Leave the default executor as the last option, which executes normal
        // container workloads.
        libcontainer::workload::default::get_executor().exec(spec)
    }

    fn validate(&self, spec: &Spec) -> Result<(), ExecutorValidationError> {
        #[cfg(feature = "wasm-wasmer")]
        match super::wasmer::get_executor().validate(spec) {
            Ok(_) => return Ok(()),
            Err(ExecutorValidationError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }
        #[cfg(feature = "wasm-wasmedge")]
        match super::wasmedge::get_executor().validate(spec) {
            Ok(_) => return Ok(()),
            Err(ExecutorValidationError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }
        #[cfg(feature = "wasm-wasmtime")]
        match super::wasmtime::get_executor().validate(spec) {
            Ok(_) => return Ok(()),
            Err(ExecutorValidationError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }

        libcontainer::workload::default::get_executor().validate(spec)
    }
}

pub fn default_executor() -> DefaultExecutor {
    DefaultExecutor {}
}
