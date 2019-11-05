use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SOCKET_ENV: &str = "RUSKCOV_INJECT_SOCK";

/// Description of an object file and its mappings into a process address space
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectInfo {
    pub pid: u32,
    pub path: PathBuf,
    pub addr: usize,
    pub phdrs: Vec<PHdr>,
}

/// Mapping of a specific PHdr in a process address space
#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PHdr {
    pub vaddr: usize,
    pub memsize: usize,
}

// Representation of a breakpoint for the architecture (1 byte for int3 on x86_64)
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct BreakpointInst(pub [u8; 1]);

// x86 int3 breakpoint
pub const BREAKPOINT: BreakpointInst = BreakpointInst([0xcc]);

/// Request from controller to bulk-set breakpoints. May be sent repeatedly, with the final set being empty.
/// Sender is expected to send reasonably sized batches with addresses in sorted order. Breakpoints must not be
/// in the injected .so.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SetBreakpointsReq {
    pub breakpoints: Vec<usize>,
}

/// Response to setting breakpoints - for each breakpoint set it returns the original value
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetBreakpointsResp {
    pub set: Vec<(usize, BreakpointInst)>,
}
