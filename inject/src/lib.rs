//! Code injected into target process via LD_PRELOAD.
//!
//! This has several roles:
//! 1. capture initial set of shared objects
//! 2. intercept dlopen and capture shared objects
//! 3. bulk setting of breakpoints
//!
//! Communication with the controlling process is via a pipe or unix domain socket.

// Always compile for injection into another process via LD_PRELOAD
#![crate_type = "cdylib"]

use inject_types::{ObjectInfo, PHdr, SetBreakpointsReq, SetBreakpointsResp};
use libc::{
    c_char, c_int, c_void, dl_iterate_phdr, dl_phdr_info, dlsym, size_t, PT_LOAD, RTLD_NEXT,
};
use std::{
    env,
    ffi::{CStr, OsStr},
    io::{BufReader, BufWriter, Write},
    mem,
    os::unix::{ffi::OsStrExt, net::UnixStream},
    path::PathBuf,
    ptr, slice,
};

extern "C" {
    fn breakpoint();
}

fn gather_phdrs() -> Vec<ObjectInfo> {
    let mut data: Vec<ObjectInfo> = Vec::new();

    unsafe extern "C" fn callback(
        info: *mut dl_phdr_info,
        _size: size_t,
        data: *mut c_void,
    ) -> c_int {
        let data: &mut Vec<ObjectInfo> = mem::transmute(data);
        let info: &dl_phdr_info = mem::transmute(info);

        let cpath = CStr::from_ptr(info.dlpi_name);
        let path = PathBuf::from(OsStr::from_bytes(cpath.to_bytes()));
        let addr = info.dlpi_addr;

        let phdrs = slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);

        let phvec: Vec<PHdr> = phdrs
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| PHdr {
                vaddr: ph.p_vaddr as usize,
                paddr: ph.p_paddr as usize,
                memsize: ph.p_memsz as usize,
                filesize: ph.p_filesz as u64,
                offset: ph.p_offset as u64,
            })
            .collect();

        let pho = ObjectInfo {
            path,
            addr: addr as usize,
            phdrs: phvec,
        };

        data.push(pho);

        0
    }
    unsafe { dl_iterate_phdr(Some(callback), mem::transmute::<_, *mut c_void>(&mut data)) };

    data
}

/// Bulk set breakpoints given a vector of addresses to set them at
fn set_breakpoints(mut breakpoints: Vec<usize>) -> SetBreakpointsResp {
    breakpoints.sort();

    unimplemented!()
}

/// Talk to controller. Expected protocol is:
/// 1. We send current state of all object files we know about, and their phdrs
/// 2. Controller sends breakpoints to set
/// 3. We send them and send responses
///
/// TODO: Better name
fn send_phdrs() {
    // Address of a unix domain socket
    let sock_path = match env::var("RUSKCOV_INJECT_SOCK") {
        Ok(path) => path,
        Err(_) => return,
    };

    let sock_rd = match UnixStream::connect(sock_path) {
        Ok(sock) => sock,
        Err(_) => return,
    };

    let sock_wr = match sock_rd.try_clone() {
        Ok(wr) => wr,
        Err(_) => return,
    };

    let mut sock_rd = BufReader::new(sock_rd);
    let mut sock_wr = BufWriter::new(sock_wr);

    let phdrs = gather_phdrs();

    bincode::serialize_into(&mut sock_wr, &phdrs).expect("sending phdrs failed");
    sock_wr.flush().expect("phdr flush failed");

    loop {
        let breakpoints: SetBreakpointsReq =
            bincode::deserialize_from(&mut sock_rd).expect("Getting breakpoint request failed");
        if breakpoints.breakpoints.is_empty() {
            break;
        }

        let resp = set_breakpoints(breakpoints.breakpoints);

        bincode::serialize_into(&mut sock_wr, &resp).expect("sending breakpoint responses failed");
        sock_wr.flush().expect("breakpoint resp flush failed");
    }
}

/// Intercept dlopen to capture added phdrs
#[no_mangle]
pub unsafe extern "C" fn dlopen(name: *mut c_char, flags: c_int) -> *mut c_void {
    let real_dlopen = dlsym(RTLD_NEXT, b"dlopen".as_ptr() as *const c_char)
        as *const extern "C" fn(*mut c_char, c_int) -> *mut c_void;

    if real_dlopen.is_null() {
        return ptr::null_mut();
    }

    let ret = (*real_dlopen)(name, flags);

    if !ret.is_null() {
        send_phdrs();
    }

    ret
}

#[ctor::ctor]
fn init_send_phdrs() {
    // Controller will be expecting phdrs immediately
    send_phdrs();
}
