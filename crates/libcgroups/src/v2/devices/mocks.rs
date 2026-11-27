// Here we duplicate the signatures of external functions and apply
// the mockall::automock macro to generate mock modules for use
// in tests, allowing us to exercise code paths without eg making syscalls

#[cfg_attr(test, automock())]
pub mod libc {
    #[cfg(target_env = "musl")]
    #[allow(non_camel_case_types)]
    pub type __rlimit_resource_t = libc::c_int;

    #[cfg(not(target_env = "musl"))]
    #[allow(non_camel_case_types)]
    pub type __rlimit_resource_t = libc::__rlimit_resource_t;

    pub fn setrlimit(_resource: __rlimit_resource_t, _rlim: *const libc::rlimit) -> libc::c_int {
        unimplemented!();
    }
}

#[cfg_attr(test, automock())]
pub mod bpf_sys {
    use std::ffi::CStr;

    use crate::v2::devices::bpf_uapi::BpfInsn;

    pub fn bpf_prog_load(
        _prog_type: u32,
        _license: &CStr,
        _insns: *const BpfInsn,
        _insns_cnt: usize,
    ) -> ::std::os::raw::c_int {
        unimplemented!();
    }

    pub fn bpf_prog_query(
        _target_fd: ::std::os::raw::c_int,
        _attach_type: u32,
        _query_flags: u32,
        _attach_flags: *mut u32,
        _prog_ids: *mut u32,
        _prog_cnt: *mut u32,
    ) -> ::std::os::raw::c_int {
        unimplemented!();
    }

    pub fn bpf_prog_get_fd_by_id(_id: u32) -> ::std::os::raw::c_int {
        unimplemented!();
    }

    pub fn bpf_prog_detach2(
        _prog_fd: ::std::os::raw::c_int,
        _attachable_fd: ::std::os::raw::c_int,
        _attach_type: u32,
    ) -> ::std::os::raw::c_int {
        unimplemented!();
    }

    pub fn bpf_prog_attach(
        _prog_fd: ::std::os::raw::c_int,
        _attachable_fd: ::std::os::raw::c_int,
        _attach_type: u32,
        _flags: ::std::os::raw::c_uint,
    ) -> ::std::os::raw::c_int {
        unimplemented!();
    }
}
