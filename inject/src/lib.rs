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

use findshlibs::{Segment, SharedLibrary, TargetSharedLibrary};
use inject_types::{
    BreakpointInst, ObjectInfo, PHdr, SetBreakpointsReq, SetBreakpointsResp, BREAKPOINT, SOCKET_ENV,
};
use itertools::Itertools;
use libc::{c_char, c_int, c_void, dlsym, size_t, RTLD_NEXT};
use std::{
    env,
    ffi::{CStr, OsStr},
    io::{BufReader, BufWriter, Write},
    mem,
    os::unix::{ffi::OsStrExt, net::UnixStream},
    path::PathBuf,
    ptr, slice,
};

mod span;

use span::Span;

extern "C" {
    fn breakpoint();
}

fn gather_phdrs() -> Vec<ObjectInfo> {
    let mut data: Vec<ObjectInfo> = Vec::new();

    TargetSharedLibrary::each(|shlib| {
        let path = PathBuf::from(shlib.name());
        let addr = shlib.virtual_memory_bias().0 as usize;
        let phvec: Vec<PHdr> = shlib
            .segments()
            .filter(|seg| seg.is_code())
            .map(|seg| PHdr {
                vaddr: seg.stated_virtual_memory_address().0 as usize,
                memsize: seg.len(),
            })
            .collect();

        let obj = ObjectInfo {
            pid: std::process::id(),
            path,
            addr: addr as usize,
            phdrs: phvec,
        };

        data.push(obj);
    });

    data
}

/// Bulk set breakpoints given a vector of addresses to set them at
fn set_breakpoints(mut breakpoints: Vec<usize>) -> SetBreakpointsResp {

    breakpoints.sort();

    let spans = breakpoints
        .into_iter()
        .map(Span::new)
        .coalesce(|prev, cur| prev.extend(cur));
    let mut res = Vec::new();

    for span in spans {
        unsafe {
            libc::mprotect(
                span.start as *mut c_void,
                span.len as size_t,
                libc::PROT_WRITE,
            )
        };

        for addr in span.addrs {
            let inst: &mut BreakpointInst = unsafe { mem::transmute(addr) };

            let old = mem::replace(inst, BREAKPOINT);

            res.push((addr, old));
        }

        unsafe {
            libc::mprotect(
                span.start as *mut c_void,
                span.len as size_t,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
    }

    SetBreakpointsResp { set: res }
}

/// Talk to controller. Expected protocol is:
/// 1. We send current state of all object files we know about, and their phdrs
/// 2. Controller sends breakpoints to set
/// 3. We send them and send responses
///
/// TODO: Better name
fn send_phdrs() {
    // Address of a unix domain socket
    let sock_path = match env::var(SOCKET_ENV) {
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
