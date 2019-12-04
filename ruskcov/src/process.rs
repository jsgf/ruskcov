//! Process model

use nix::unistd::Pid;
use std::{
    collections::{BTreeMap, HashMap},
    mem,
    sync::Arc,
};

use crate::Location;

#[derive(Debug, Clone)]
pub struct Segment {
    len: u64,
}

#[derive(Debug, Clone)]
pub struct AddressSpace {
    /// Breakpoints by address
    breakpoints: HashMap<u64, Location>,
    /// Segment by address
    segments: BTreeMap<u64, Segment>,
}

/// Model both processes and threads. The only distinction is that threads share an address space
#[derive(Debug, Clone)]
pub struct Process {
    pid: Pid,
    state: ProcessState,
    addrspace: Arc<AddressSpace>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProcessState {
    /// Newly created; sole owner of address space (ie, main thread)
    New,
    /// Running
    Running,
    /// Stopped by ptrace event
    Stopped,
    /// Exiting
    Exiting,
}

impl Process {
    pub fn new(
        pid: Pid,
        segments: impl IntoIterator<Item = (u64, u64)>,
        breakpoints: impl IntoIterator<Item = (u64, Location)>,
    ) -> Self {
        let addrspace = AddressSpace {
            breakpoints: breakpoints.into_iter().collect(),
            segments: segments
                .into_iter()
                .map(|(addr, len)| (addr, Segment { len }))
                .collect(),
        };
        Process {
            pid,
            state: ProcessState::New,
            addrspace: Arc::new(addrspace),
        }
    }

    pub fn new_thread(&self, pid: Pid) -> Self {
        Process {
            pid,
            state: ProcessState::Running,
            addrspace: Arc::clone(&self.addrspace),
        }
    }

    pub fn exec(&mut self, segments: impl IntoIterator<Item = (u64, u64)>) {
        let addrspace = AddressSpace {
            breakpoints: Default::default(),
            segments: segments
                .into_iter()
                .map(|(addr, len)| (addr, Segment { len }))
                .collect(),
        };
        let _ = mem::replace(&mut self.addrspace, Arc::new(addrspace));
    }
}
