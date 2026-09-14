//! Entry point setup: argv/envp/apple construction, initializer calls and
//! the jump that finally sets the target's PC.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use crate::image::ImageKind;
use crate::loader::Registry;
use crate::vlog;

type EntryFn = unsafe extern "C" fn(
    c_int,
    *const *const c_char,
    *const *const c_char,
    *const *const c_char,
) -> c_int;

type InitFn = unsafe extern "C" fn();

static ARGC_SHIM: AtomicI32 = AtomicI32::new(0);
/// Points at the argv array (first *const c_char slot).
static ARGV_SHIM: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());
static EXEC_PATH: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());
static DYLD_PRIVATE: usize = 0;

/// Symbols we intercept instead of resolving through the host.
pub fn shim_lookup(name: &str) -> Option<usize> {
    match name {
        "_NSGetArgc" => Some(nsgetargc as *const () as usize),
        "_NSGetArgv" => Some(nsgetargv as *const () as usize),
        "_NSGetExecutablePath" => Some(nsgetexecutablepath as *const () as usize),
        "dyld_stub_binder" => Some(stub_binder_placeholder as *const () as usize),
        "__dyld_private" => Some(std::ptr::addr_of!(DYLD_PRIVATE) as usize),
        // TLV descriptors' thunk word is a bind to __tlv_bootstrap; ours does
        // the per-thread bookkeeping (hidden in the host, so we can't dlsym it).
        "__tlv_bootstrap" => Some(crate::tls::tlv_thunk as *const () as usize),
        _ => None,
    }
}

#[unsafe(no_mangle)]
extern "C" fn nsgetargc() -> *mut c_int {
    ARGC_SHIM.as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn nsgetargv() -> *mut *mut *mut c_char {
    ARGV_SHIM.as_ptr() as *mut *mut *mut c_char
}

#[unsafe(no_mangle)]
unsafe extern "C" fn nsgetexecutablepath(buf: *mut c_char, bufsize: *mut u32) -> c_int {
    unsafe {
        let p = EXEC_PATH.load(Ordering::Relaxed);
        if p.is_null() || bufsize.is_null() {
            return -1;
        }
        let len = CStr::from_ptr(p).to_bytes_with_nul().len();
        let cap = *bufsize as usize;
        if buf.is_null() || cap < len {
            *bufsize = len as u32;
            return -1;
        }
        std::ptr::copy_nonoverlapping(p, buf, len);
        *bufsize = len as u32;
        0
    }
}

/// Lazy pointers are filled eagerly, so the binder should never run; arm64
/// text is never patched by the loader.
#[unsafe(no_mangle)]
extern "C" fn stub_binder_placeholder() -> ! {
    eprintln!("mldr: dyld_stub_binder was called; eager binding failed somewhere");
    std::process::exit(127);
}

/// Runs the target on a thread whose stack matches LC_MAIN.stacksize (the
/// kernel would grant `main` that much stack via the normal exec path).
pub fn run_target(reg: &Registry, argv: Vec<String>) -> ! {
    let stack_size = {
        let m = reg.images[reg.main].macho();
        (m.entry_stack_size.unwrap_or(0) as usize).max(8 * 1024 * 1024)
    };
    vlog!("target stack size {stack_size:#x}");
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn_scoped(scope, || run_entry(reg, argv))
            .expect("failed to spawn target thread");
        let _ = handle.join();
    });
    // Only reachable if the target thread died without calling exit().
    std::process::exit(127);
}

/// Runs `entry(argc, argv, envp, apple)` and exits with its return value. On
/// arm64 macOS there is no crt glue: the entry point is `main` itself, called
/// with registers.
fn run_entry(reg: &Registry, argv: Vec<String>) -> ! {
    let img = &reg.images[reg.main];
    let m = img.macho();
    let text = m.text_segment().expect("main executable has no __TEXT segment");
    let entry_off = m.entry_off.expect("main executable has no LC_MAIN");
    let entry_addr = img.addr_of(text.vmaddr + entry_off);

    let cargs: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap_or_default())
        .collect();
    let mut argv_ptrs: Vec<*const c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let envp = unsafe { crate::sys::environ };
    let exec_path = cargs.first().cloned().unwrap_or_default();
    let apple: Vec<*const c_char> = vec![exec_path.as_ptr(), std::ptr::null()];

    ARGC_SHIM.store((argv_ptrs.len() - 1) as i32, Ordering::Relaxed);
    ARGV_SHIM.store(argv_ptrs.as_ptr() as *mut c_char, Ordering::Relaxed);
    EXEC_PATH.store(exec_path.as_ptr() as *mut c_char, Ordering::Relaxed);

    for idx in init_order(reg) {
        for f in &reg.images[idx].init_funcs {
            vlog!(
                "running initializer {:#x} in {}",
                f,
                reg.images[idx].install_name
            );
            let f: InitFn = unsafe { std::mem::transmute(*f) };
            unsafe { f() };
        }
    }

    vlog!("entry point {entry_addr:#x}");
    let f: EntryFn = unsafe { std::mem::transmute(entry_addr) };
    std::io::Write::flush(&mut std::io::stdout()).ok();
    std::io::Write::flush(&mut std::io::stderr()).ok();
    vlog!("jumping to target");
    let ret = unsafe {
        f(
            argv_ptrs.len() as c_int - 1,
            argv_ptrs.as_ptr(),
            envp as *const *const c_char,
            apple.as_ptr(),
        )
    };
    std::process::exit(ret);
}

/// Dependencies before dependents; the main executable runs last.
fn init_order(reg: &Registry) -> Vec<usize> {
    fn visit(reg: &Registry, i: usize, seen: &mut [bool], order: &mut Vec<usize>) {
        if seen[i] {
            return;
        }
        seen[i] = true;
        for &d in &reg.images[i].deps {
            visit(reg, d, seen, order);
        }
        if reg.images[i].kind != ImageKind::SystemBridged {
            order.push(i);
        }
    }
    let mut order = Vec::new();
    let mut seen = vec![false; reg.images.len()];
    visit(reg, reg.main, &mut seen, &mut order);
    order
}
