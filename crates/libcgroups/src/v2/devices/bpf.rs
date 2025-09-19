#[derive(Clone)]
pub struct ProgramInfo {
    pub id: u32,
    pub fd: i32,
}

#[derive(thiserror::Error, Debug)]
pub enum BpfError {
    #[error(transparent)]
    Errno(#[from] errno::Errno),
    #[error("Failed to increase rlimit")]
    FailedToIncreaseRLimit,
}

#[cfg_attr(test, automock)]
pub mod prog {
    use std::os::unix::io::RawFd;
    use std::ptr;

    use libbpf_sys::{BPF_CGROUP_DEVICE, BPF_F_ALLOW_MULTI, BPF_PROG_TYPE_CGROUP_DEVICE, bpf_insn};
    #[cfg(not(test))]
    use libbpf_sys::{
        bpf_prog_attach, bpf_prog_detach2, bpf_prog_get_fd_by_id, bpf_prog_load, bpf_prog_query,
    };
    #[cfg(not(test))]
    use libc::setrlimit;
    use libc::{ENOSPC, RLIMIT_MEMLOCK, rlimit};

    use super::ProgramInfo;
    // TODO: consider use of #[mockall_double]
    #[cfg(test)]
    use crate::v2::devices::mocks::mock_libbpf_sys::{
        bpf_prog_attach, bpf_prog_detach2, bpf_prog_get_fd_by_id, bpf_prog_load, bpf_prog_query,
    };
    // mocks
    // TODO: consider use of #[mockall_double]
    #[cfg(test)]
    use crate::v2::devices::mocks::mock_libc::setrlimit;

    pub fn load(license: &str, insns: &[u8]) -> Result<RawFd, super::BpfError> {
        let insns_cnt = insns.len() / std::mem::size_of::<bpf_insn>();
        let insns = insns as *const _ as *const bpf_insn;
        let mut opts = libbpf_sys::bpf_prog_load_opts {
            kern_version: 0,
            log_buf: ptr::null_mut::<::std::os::raw::c_char>(),
            log_size: 0,
            ..Default::default()
        };
        #[allow(unused_unsafe)]
        let prog_fd = unsafe {
            bpf_prog_load(
                BPF_PROG_TYPE_CGROUP_DEVICE,
                ptr::null::<::std::os::raw::c_char>(),
                license as *const _ as *const ::std::os::raw::c_char,
                insns,
                insns_cnt as u64,
                &mut opts as *mut libbpf_sys::bpf_prog_load_opts,
            )
        };

        if prog_fd < 0 {
            return Err(errno::errno().into());
        }
        Ok(prog_fd)
    }

    /// Given a fd for a cgroup, collect the programs associated with it
    pub fn query(cgroup_fd: RawFd) -> Result<Vec<ProgramInfo>, super::BpfError> {
        let mut prog_ids: Vec<u32> = vec![0_u32; 64];
        let mut attach_flags = 0_u32;
        for _ in 0..10 {
            let mut prog_cnt = prog_ids.len() as u32;
            #[allow(unused_unsafe)]
            let ret = unsafe {
                // collect ids for bpf programs
                bpf_prog_query(
                    cgroup_fd,
                    BPF_CGROUP_DEVICE,
                    0,
                    &mut attach_flags,
                    &prog_ids[0] as *const u32 as *mut u32,
                    &mut prog_cnt,
                )
            };
            if ret != 0 {
                let err = errno::errno();
                if err.0 == ENOSPC {
                    assert!(prog_cnt as usize > prog_ids.len());

                    // allocate more space and try again
                    prog_ids.resize(prog_cnt as usize, 0);
                    continue;
                }

                return Err(err.into());
            }

            prog_ids.resize(prog_cnt as usize, 0);
            break;
        }

        let mut prog_fds = Vec::with_capacity(prog_ids.len());
        for prog_id in &prog_ids {
            // collect fds for programs by getting their ids
            #[allow(unused_unsafe)]
            let prog_fd = unsafe { bpf_prog_get_fd_by_id(*prog_id) };
            if prog_fd < 0 {
                tracing::debug!("bpf_prog_get_fd_by_id failed: {}", errno::errno());
                continue;
            }
            prog_fds.push(ProgramInfo {
                id: *prog_id,
                fd: prog_fd,
            });
        }
        Ok(prog_fds)
    }

    pub fn detach2(prog_fd: RawFd, cgroup_fd: RawFd) -> Result<(), super::BpfError> {
        #[allow(unused_unsafe)]
        let ret = unsafe { bpf_prog_detach2(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE) };
        if ret != 0 {
            return Err(errno::errno().into());
        }
        Ok(())
    }

    pub fn attach(prog_fd: RawFd, cgroup_fd: RawFd) -> Result<(), super::BpfError> {
        #[allow(unused_unsafe)]
        let ret =
            unsafe { bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE, BPF_F_ALLOW_MULTI) };

        if ret != 0 {
            return Err(errno::errno().into());
        }
        Ok(())
    }

    pub fn bump_memlock_rlimit() -> Result<(), super::BpfError> {
        let rlimit = rlimit {
            rlim_cur: 128 << 20,
            rlim_max: 128 << 20,
        };

        #[allow(unused_unsafe)]
        if unsafe { setrlimit(RLIMIT_MEMLOCK, &rlimit) } != 0 {
            return Err(super::BpfError::FailedToIncreaseRLimit);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use errno::{Errno, set_errno};
    use libc::{ENOSPC, ENOSYS};
    use serial_test::serial;

    use super::prog;
    use crate::v2::devices::mocks::{mock_libbpf_sys, mock_libc};

    #[test]
    #[serial(libbpf_sys)] // mock contexts are shared
    fn test_bpf_load() {
        // eBPF uses 64-bit instructions
        let instruction_zero: &[u8] = &[0x0, 0x0, 0x0, 0x0];
        let instruction_one: &[u8] = &[0xF, 0xF, 0xF, 0xF];

        // arrange
        let license = "Apache";
        let instructions = [instruction_zero, instruction_one].concat();
        let load = mock_libbpf_sys::bpf_prog_load_context();

        // expect
        load.expect().once().returning(|_, _, _, _, _, _| 32);

        // act
        let fd = prog::load(license, &instructions).expect("successfully calls load");

        // assert
        assert_eq!(fd, 32);
    }

    #[test]
    #[serial(libbpf_sys)] // mock contexts are shared
    fn test_bpf_attach() {
        // arrange
        let attach = mock_libbpf_sys::bpf_prog_attach_context();

        // expect
        attach.expect().once().returning(|_, _, _, _| 0);

        // act
        let r = prog::attach(0, 0);

        // assert
        assert!(r.is_ok());
    }

    #[test]
    #[serial(libbpf_sys)] // mock contexts are shared
    fn test_bpf_load_error() {
        // eBPF uses 64-bit instructions
        let instruction_zero: &[u8] = &[0x0, 0x0, 0x0, 0x0];
        let instruction_one: &[u8] = &[0xF, 0xF, 0xF, 0xF];

        // arrange
        let license = "Apache";
        let instructions = [instruction_zero, instruction_one].concat();
        let load = mock_libbpf_sys::bpf_prog_load_context();

        // expect
        load.expect().once().returning(|_, _, _, _, _, _| -1);

        // act
        let error_result = prog::load(license, &instructions);

        // assert
        assert!(error_result.is_err());
    }

    #[test]
    #[serial(libbpf_sys)] // mock contexts are shared
    fn test_bpf_query() {
        // arrange
        let query = mock_libbpf_sys::bpf_prog_query_context();
        let get_fd_by_id = mock_libbpf_sys::bpf_prog_get_fd_by_id_context();

        // expect
        query.expect().once().returning(
            |_target_fd: std::os::raw::c_int,
             _type_: libbpf_sys::bpf_attach_type,
             _query_flags: libbpf_sys::__u32,
             _attach_flags: *mut libbpf_sys::__u32,
             prog_ids: *mut libbpf_sys::__u32,
             prog_cnt: *mut libbpf_sys::__u32|
             -> ::std::os::raw::c_int {
                // deref the ptr and fill it with some "ids"
                // also set the prog_cnt to 4
                set_errno(Errno(0));
                unsafe {
                    *prog_cnt = 4;
                    let id_array = std::slice::from_raw_parts_mut(prog_ids, 4_usize);
                    id_array[0] = 1;
                    id_array[1] = 2;
                    id_array[2] = 3;
                    id_array[3] = 4;
                }
                0
            },
        );
        get_fd_by_id.expect().times(4).returning(|fd| {
            // return the same fd if it's not 0
            if fd > 0 {
                return fd as std::os::raw::c_int;
            }
            -1
        });

        // act
        let info = prog::query(0).expect("Able to successfully query");

        // assert
        assert_eq!(info.first().unwrap().id, 1);
        assert_eq!(info.len(), 4);
    }

    #[test]
    #[serial(libbpf_sys)] // mock contexts are shared
    fn test_bpf_query_recoverable_error() {
        // arrange
        let query = mock_libbpf_sys::bpf_prog_query_context();
        let get_fd_by_id = mock_libbpf_sys::bpf_prog_get_fd_by_id_context();

        // expect
        query.expect().times(2).returning(
            |_target_fd: std::os::raw::c_int,
             _type_: libbpf_sys::bpf_attach_type,
             _query_flags: libbpf_sys::__u32,
             _attach_flags: *mut libbpf_sys::__u32,
             prog_ids: *mut libbpf_sys::__u32,
             prog_cnt: *mut libbpf_sys::__u32|
             -> ::std::os::raw::c_int {
                unsafe {
                    if *prog_cnt == 64 {
                        set_errno(Errno(ENOSPC));
                        *prog_cnt = 128;
                        return 1;
                    }
                    let id_array = std::slice::from_raw_parts_mut(prog_ids, 128_usize);
                    for (i, item) in id_array.iter_mut().enumerate() {
                        *item = (i + 1) as u32;
                    }
                }
                0
            },
        );
        get_fd_by_id.expect().times(128).returning(|fd| {
            // return the same fd if it's not 0
            if fd > 0 {
                return fd as std::os::raw::c_int;
            }
            -1
        });

        // act
        let info = prog::query(0).expect("Able to successfully query");

        // assert
        assert_eq!(info.first().unwrap().id, 1);
        assert_eq!(info.len(), 128);
    }

    #[test]
    #[serial(libbpf_sys)] // mock contexts are shared
    fn test_bpf_query_other_error() {
        // arrange
        let query = mock_libbpf_sys::bpf_prog_query_context();
        let get_fd_by_id = mock_libbpf_sys::bpf_prog_get_fd_by_id_context();

        // expect
        query.expect().times(1).returning(
            |_target_fd: std::os::raw::c_int,
             _type_: libbpf_sys::bpf_attach_type,
             _query_flags: libbpf_sys::__u32,
             _attach_flags: *mut libbpf_sys::__u32,
             _prog_ids: *mut libbpf_sys::__u32,
             _prog_cnt: *mut libbpf_sys::__u32|
             -> ::std::os::raw::c_int {
                set_errno(Errno(ENOSYS));
                1
            },
        );
        get_fd_by_id.expect().never();

        // act
        let error = prog::query(0);

        // assert
        assert!(error.is_err());
    }

    #[test]
    #[serial(libbpf_sys)] // mock contexts are shared
    fn test_bpf_detach2() {
        // arrange
        let detach2 = mock_libbpf_sys::bpf_prog_detach2_context();

        // expect
        detach2.expect().once().returning(|_, _, _| 0);

        // act
        let r = prog::detach2(0, 0);

        // assert
        assert!(r.is_ok());
    }

    #[test]
    #[serial(libbpf_sys)] // mock contexts are shared
    fn test_bpf_detach2_error() {
        // arrange
        let detach2 = mock_libbpf_sys::bpf_prog_detach2_context();

        // expect
        detach2.expect().once().returning(|_, _, _| 1);

        // act
        let r = prog::detach2(0, 0);

        // assert
        assert!(r.is_err());
    }

    #[test]
    #[serial(libc)] // mock contexts are shared
    fn test_bump_memlock_rlimit() {
        // arrange
        let setrlimit = mock_libc::setrlimit_context();

        // expect
        setrlimit.expect().once().returning(|_, _| 0);

        // act
        let r = prog::bump_memlock_rlimit();

        // assert
        assert!(r.is_ok());
    }

    #[test]
    #[serial(libc)] // mock contexts are shared
    fn test_bump_memlock_rlimit_error() {
        // arrange
        let setrlimit = mock_libc::setrlimit_context();

        // expect
        setrlimit.expect().once().returning(|_, _| 1);

        // act
        let r = prog::bump_memlock_rlimit();

        // assert
        assert!(r.is_err());
    }
}
