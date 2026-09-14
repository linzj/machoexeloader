//! Target entry: create a raw pthread with the stack the image asks for,
//! build a kernel-style initial stack ([argc][argv][envp][auxv]) at the top
//! of that thread's real stack, install the target TLS block, and jump to
//! the ELF entry point with rdx=0 (rtld_fini).

use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;

use crate::elf::ElfFile;
use crate::image::Image;
use crate::sys;
use crate::tls;
use crate::{rerr, vlog};

struct EntryParams {
    entry: usize,
    argv: Vec<*const c_char>,
    env: Vec<*const c_char>,
    auxv: Vec<u64>,
}

pub fn run_target(img: &Image, argv: &[String]) -> ! {
    crate::shim::patch_program_invocation();
    if crate::diag::verbose() {
        install_crash_reporter();
    }

    // argv strings: heap CStrings, leaked for the process lifetime.
    let mut argv_c: Vec<*const c_char> = Vec::with_capacity(argv.len());
    for a in argv {
        let c = CString::new(a.as_str()).unwrap_or_default();
        argv_c.push(Box::leak(Box::new(c)).as_ptr());
    }
    let env = env_pointers();
    let auxv = build_auxv(&img.elf, img);

    let params = Box::new(EntryParams {
        entry: img.entry_addr(),
        argv: argv_c,
        env,
        auxv,
    });
    let stack = img.stack_size();
    vlog!(
        "entry: thread stack {:#x}, entry {:#x}, argc {}",
        stack,
        params.entry,
        params.argv.len()
    );
    match sys::spawn_thread(stack, entry_thread, Box::into_raw(params) as *mut c_void) {
        Ok(tid) => {
            sys::join_thread(tid);
            rerr!("target entry thread returned without exiting");
            unsafe { sys::_exit(127) };
        }
        Err(e) => {
            rerr!("{e}");
            unsafe { sys::_exit(127) };
        }
    }
}

extern "C" fn entry_thread(p: *mut c_void) -> *mut c_void {
    let params = unsafe { Box::from_raw(p as *mut EntryParams) };
    tls::install_for_current_thread();
    let frame = unsafe { build_initial_stack(&params) };
    vlog!(
        "entry: jumping to {:#x} with initial rsp {:#x}",
        params.entry,
        frame as usize
    );
    unsafe { jump_to_entry(frame, params.entry) }
}

/// Host environment pointers (inherited verbatim; the target and the host
/// share one libc, so getenv/setenv stay coherent).
fn env_pointers() -> Vec<*const c_char> {
    let mut out = Vec::new();
    unsafe {
        let mut p = sys::environ;
        while !p.is_null() && !(*p).is_null() {
            out.push(*p as *const c_char);
            p = p.add(1);
        }
    }
    out
}

fn build_auxv(elf: &ElfFile, img: &Image) -> Vec<u64> {
    let g = sys::auxval;
    let mut a: Vec<u64> = Vec::with_capacity(48);
    let phnum = elf.phdrs.len() as u64;
    let mut push = |t: u64, v: u64| {
        a.push(t);
        a.push(v);
    };
    push(sys::AT_PHDR, img.base + elf.phoff);
    push(sys::AT_PHENT, 56);
    push(sys::AT_PHNUM, phnum);
    push(sys::AT_PAGESZ, sys::page_size() as u64);
    push(sys::AT_BASE, 0);
    push(sys::AT_FLAGS, 0);
    push(sys::AT_ENTRY, img.base + elf.entry);
    push(sys::AT_UID, g(sys::AT_UID));
    push(sys::AT_EUID, g(sys::AT_EUID));
    push(sys::AT_GID, g(sys::AT_GID));
    push(sys::AT_EGID, g(sys::AT_EGID));
    push(sys::AT_PLATFORM, g(sys::AT_PLATFORM));
    push(sys::AT_HWCAP, g(sys::AT_HWCAP));
    push(sys::AT_HWCAP2, g(sys::AT_HWCAP2));
    push(sys::AT_CLKTCK, g(sys::AT_CLKTCK));
    push(sys::AT_SECURE, 0);
    push(sys::AT_RANDOM, g(sys::AT_RANDOM));
    push(sys::AT_SYSINFO_EHDR, g(sys::AT_SYSINFO_EHDR));
    if let Some(p) = crate::shim::target_path_ptr() {
        push(sys::AT_EXECFN, p as u64);
    }
    push(0, 0); // AT_NULL
    a
}

/// Lay out the initial stack the way the kernel would:
/// [argc][argv...][NULL][envp...][NULL][auxv...][AT_NULL], 16-aligned.
unsafe fn build_initial_stack(p: &EntryParams) -> *const u64 {
    // pthread_getattr_np reports the whole stack mapping, whose top end is
    // occupied by the thread's TCB and static TLS blocks. The safe initial-sp
    // is derived from where we are actually executing: this thread just
    // started, so the current frame is only a few hundred bytes below the
    // kernel-provided top of the usable stack.
    let here = &p as *const _ as usize;
    let top = (here - 256) & !0xf;
    if let Ok((base, size)) = sys::current_stack_bounds() {
        vlog!(
            "entry: stack mapping {base:#x}+{size:#x}, using top {top:#x}",
        );
        if top < base + 4096 || top > base + size {
            rerr!("entry: derived stack top {top:#x} outside mapping");
            unsafe { sys::_exit(127) };
        }
    } else {
        rerr!("entry: cannot read stack bounds");
        unsafe { sys::_exit(127) };
    }
    let words = 1 + (p.argv.len() + 1) + (p.env.len() + 1) + p.auxv.len() + 1;
    let sp = (top - words * 8) & !0xf;
    let mut w = sp as *mut u64;
    unsafe {
        *w = p.argv.len() as u64;
        w = w.add(1);
        for &a in &p.argv {
            *w = a as u64;
            w = w.add(1);
        }
        *w = 0;
        w = w.add(1);
        for &e in &p.env {
            *w = e as u64;
            w = w.add(1);
        }
        *w = 0;
        w = w.add(1);
        for &v in &p.auxv {
            *w = v;
            w = w.add(1);
        }
        *w = 0;
    }
    sp as *const u64
}

/// rdi = initial rsp, rsi = entry. xor edx sets rtld_fini = NULL: the host
/// ld.so registered its own fini at startup; the target's crt only forwards
/// this value into __libc_start_main, which we implement ourselves.
#[unsafe(naked)]
unsafe extern "C" fn jump_to_entry(_frame: *const u64, _entry: usize) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "xor edx, edx",
        "jmp rsi",
    )
}

// ---- crash reporter (verbose only) ----------------------------------------

#[repr(C)]
struct Sigaction {
    handler: usize,
    mask: [u64; 16],
    flags: c_int,
    restorer: usize,
}

#[repr(C)]
struct StackT {
    ss_sp: *mut c_void,
    ss_flags: c_int,
    ss_size: usize,
}

const SIGSEGV: c_int = 11;
const SIGBUS: c_int = 7;
const SIGILL: c_int = 4;
const SA_SIGINFO: c_int = 4;
const SA_ONSTACK: c_int = 0x0800_0000;

unsafe extern "C" {
    fn sigaction(sig: c_int, act: *const Sigaction, old: *mut Sigaction) -> c_int;
    fn sigaltstack(ss: *const StackT, old: *mut StackT) -> c_int;
}

static mut ALT_STACK: [u8; 64 * 1024] = [0; 64 * 1024];

fn install_crash_reporter() {
    unsafe {
        let ss = StackT {
            ss_sp: core::ptr::addr_of_mut!(ALT_STACK) as *mut c_void,
            ss_flags: 0,
            ss_size: 64 * 1024,
        };
        sigaltstack(&ss, ptr::null_mut());
        let act = Sigaction {
            handler: crash_handler as *const () as usize,
            mask: [0; 16],
            flags: SA_SIGINFO | SA_ONSTACK,
            restorer: 0,
        };
        for sig in [SIGSEGV, SIGBUS, SIGILL] {
            sigaction(sig, &act, ptr::null_mut());
        }
    }
}

extern "C" fn crash_handler(sig: c_int, info: *mut c_void, ctx: *mut c_void) -> ! {
    unsafe {
        let addr = if info.is_null() {
            0
        } else {
            *(info as *const u64).add(2) // si_addr at offset 16
        };
        // ucontext_t: uc_mcontext at 40; gregs[REG_RIP=16] / gregs[REG_RSP=15]
        let gregs = (ctx as *const u8).add(40) as *const u64;
        let rip = if ctx.is_null() { 0 } else { *gregs.add(16) };
        let rsp = if ctx.is_null() { 0 } else { *gregs.add(15) };
        rerr!("signal {sig}: addr={addr:#x} rip={rip:#x} rsp={rsp:#x}");
        crate::shim::describe_addr(rip);
        crate::shim::roll_call();
        sys::_exit(128 + sig);
    }
}
