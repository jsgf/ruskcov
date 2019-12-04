use libc::c_void;
pub use nix::{
    sys::ptrace::{cont, seize, Event, Options},
    unistd::Pid,
    Result,
};
use std::mem::{self, MaybeUninit};

const NT_PRSTATUS: u32 = 1;
const NT_PRFPREG: u32 = 2;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum VoidReg {}

impl From<VoidReg> for u64 {
    fn from(v: VoidReg) -> u64 {
        unreachable!()
    }
}

#[cfg(target_arch = "x86_64")]
type Reg64 = u64;

#[cfg(not(target_arch = "x86_64"))]
type Reg64 = VoidReg;

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RegsX86_64 {
    pub r15: Reg64,
    pub r14: Reg64,
    pub r13: Reg64,
    pub r12: Reg64,
    pub rbp: Reg64,
    pub rbx: Reg64,
    pub r11: Reg64,
    pub r10: Reg64,
    pub r9: Reg64,
    pub r8: Reg64,
    pub rax: Reg64,
    pub rcx: Reg64,
    pub rdx: Reg64,
    pub rsi: Reg64,
    pub rdi: Reg64,
    pub orig_rax: Reg64,
    pub rip: Reg64,
    pub cs: Reg64,
    pub eflags: Reg64,
    pub rsp: Reg64,
    pub ss: Reg64,
    pub fs_base: Reg64,
    pub gs_base: Reg64,
    pub ds: Reg64,
    pub es: Reg64,
    pub fs: Reg64,
    pub gs: Reg64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RegsI386 {
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub eax: u32,
    pub xds: u32,
    pub xes: u32,
    pub xfs: u32,
    pub xgs: u32,
    pub orig_eax: u32,
    pub eip: u32,
    pub xcs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub xss: u32,
}

pub enum UserRegs {
    X86_64(RegsX86_64),
    I386(RegsI386),
}

union RegUnion {
    x86_64: RegsX86_64,
    i386: RegsI386,
}

/// Get process registers, handling both 32 bit and 64 bit processes.
pub fn getregs(pid: Pid) -> Result<UserRegs> {
    unsafe {
        use nix::sys::ptrace;

        let mut regs = MaybeUninit::<RegUnion>::uninit();
        let mut iov = libc::iovec {
            iov_base: mem::transmute(regs.as_mut_ptr()),
            iov_len: mem::size_of_val(&regs),
        };
        let res = libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid.as_raw(),
            NT_PRSTATUS as usize,
            &mut iov,
        );
        if res < 0 {
            let errno = nix::errno::Errno::from_i32(res as i32);
            return Err(nix::Error::from(errno));
        }
        let regs = regs.assume_init();

        const I386SIZE: usize = mem::size_of::<RegsI386>();
        const X8664SIZE: usize = mem::size_of::<RegsX86_64>();

        match iov.iov_len {
            I386SIZE => Ok(UserRegs::I386(regs.i386)),
            X8664SIZE => Ok(UserRegs::X86_64(regs.x86_64)),
            _ => panic!("unknown size {}", iov.iov_len),
        }
    }
}
