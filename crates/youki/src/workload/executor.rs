use libcontainer::oci_spec::runtime::Spec;
use libcontainer::workload::{
    ContainerExecutor, Executor, ExecutorError, ExecutorValidationError, HostExecutor,
};

#[derive(Clone)]
pub struct DefaultExecutor {
    // Unlike the wasm executors, which are stateless and created for each dispatch
    // by `get_executor()`, the krun executor is stateful: the krun context created
    // in `HostExecutor::modify_spec` must survive the fork and be used in
    // `ContainerExecutor::exec`. So it is created once here and must not be
    // re-created per dispatch, or the context is lost.
    #[cfg(feature = "krun")]
    libkrun: super::libkrun::LibkrunExecutor,
}

impl DefaultExecutor {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "krun")]
            libkrun: super::libkrun::get_executor(),
        }
    }
}

impl HostExecutor for DefaultExecutor {
    fn modify_spec(&self, spec: Spec) -> Result<Spec, ExecutorError> {
        #[cfg(feature = "krun")]
        {
            if super::libkrun::can_handle(&spec) {
                return self.libkrun.modify_spec(spec);
            }
        }
        Ok(spec)
    }
}

impl ContainerExecutor for DefaultExecutor {
    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        #[cfg(feature = "wasm-wasmer")]
        match super::wasmer::get_executor().exec(spec) {
            Ok(_) => return Ok(()),
            Err(ExecutorError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }
        #[cfg(feature = "wasm-wasmedge")]
        match super::wasmedge::get_executor().exec(spec) {
            Ok(_) => return Ok(()),
            Err(ExecutorError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }
        #[cfg(feature = "wasm-wasmtime")]
        match super::wasmtime::get_executor().exec(spec) {
            Ok(_) => return Ok(()),
            Err(ExecutorError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }
        #[cfg(feature = "krun")]
        {
            match self.libkrun.exec(spec) {
                Ok(_) => return Ok(()),
                Err(ExecutorError::CantHandle(_)) => (),
                Err(err) => return Err(err),
            }
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
        #[cfg(feature = "krun")]
        match self.libkrun.validate(spec) {
            Ok(_) => return Ok(()),
            Err(ExecutorValidationError::CantHandle(_)) => (),
            Err(err) => return Err(err),
        }
        libcontainer::workload::default::get_executor().validate(spec)
    }
}

impl Executor for DefaultExecutor {}

pub fn default_executor() -> DefaultExecutor {
    DefaultExecutor::new()
}
