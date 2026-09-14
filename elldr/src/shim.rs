//! Symbols in the target that elldr must own rather than forward: process
//! startup (`__libc_start_main`), thread bootstrap (`pthread_create`),
//! `/proc/self/exe` identity, and dl introspection. Mirrors peldr's IAT shim
//! table (Shim table injected into the target's IAT).

use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crate::elf::ExportSym;
use crate::image::Image;
use crate::sys;
use crate::{rerr, vlog};

// ---- host-side implementations ("reals") ---------------------------------

struct Reals {
    pthread_create: usize,
    dl_iterate_phdr: usize,
    dladdr: usize,
    dlsym: usize,
    readlink: usize,
    readlinkat: usize,
    open: usize,
    openat: usize,
    fopen: usize,
    syscall: usize,
    exit: usize,
    cxa_atexit: usize,
    tls_get_addr: usize,
}

static REALS: OnceLock<Reals> = OnceLock::new();

pub fn init_reals() -> Result<(), String> {
    let need =
        |n: &str| sys::dlsym_default(n).ok_or_else(|| format!("host symbol {n} not found"));
    let r = Reals {
        pthread_create: need("pthread_create")?,
        dl_iterate_phdr: need("dl_iterate_phdr")?,
        dladdr: need("dladdr")?,
        dlsym: need("dlsym")?,
        readlink: need("readlink")?,
        readlinkat: need("readlinkat")?,
        open: need("open")?,
        openat: need("openat")?,
        fopen: need("fopen")?,
        syscall: need("syscall")?,
        exit: need("exit")?,
        cxa_atexit: need("__cxa_atexit")?,
        tls_get_addr: need("__tls_get_addr")?,
    };
    let _ = REALS.set(r);
    sample_adds_subs();
    Ok(())
}

fn reals() -> &'static Reals {
    REALS.get().expect("shim::init_reals() not called")
}

// ---- target identity ------------------------------------------------------

/// struct dl_phdr_info (glibc x86_64 layout).
#[repr(C)]
pub struct DlPhdrInfo {
    pub dlpi_addr: u64,
    pub dlpi_name: *const c_char,
    pub dlpi_phdr: *const c_void,
    pub dlpi_phnum: u16,
    pub dlpi_adds: u64,
    pub dlpi_subs: u64,
    pub dlpi_tls_modid: usize,
    pub dlpi_tls_data: *mut c_void,
}

/// struct Dl_info
#[repr(C)]
pub struct DlInfo {
    pub dli_fname: *const c_char,
    pub dli_fbase: *mut c_void,
    pub dli_sname: *const c_char,
    pub dli_saddr: *mut c_void,
}

struct TargetImage {
    base: u64,
    end: u64,
    phdr: usize,
    phnum: u16,
    has_tls: bool,
    path: &'static CString,
    /// glibc reports an empty dlpi_name for the main program; match that.
    dlpi_name: &'static CString,
    exports: Vec<ExportSym>,
}

static TARGET: OnceLock<TargetImage> = OnceLock::new();
static ADDS: AtomicUsize = AtomicUsize::new(0);
static SUBS: AtomicUsize = AtomicUsize::new(0);

/// Program identity overrides: addresses of our own `char *` variables that
/// the target's GOT binds to when it references program_invocation_*.
static PROG_NAME: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());
static PROG_SHORT_NAME: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());

pub fn set_target_path(path: &Path) -> Result<(), String> {
    // Leaked on purpose: the strings must live for the process lifetime.
    let full = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| format!("path contains NUL: {}", path.display()))?;
    let base = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".to_string());
    let short = CString::new(base).map_err(|_| "path contains NUL".to_string())?;
    let full: &'static CString = Box::leak(Box::new(full));
    let short: &'static CString = Box::leak(Box::new(short));
    PROG_NAME.store(full.as_ptr() as *mut c_char, Ordering::Relaxed);
    PROG_SHORT_NAME.store(short.as_ptr() as *mut c_char, Ordering::Relaxed);
    TARGET_PATH.set(full).ok();
    Ok(())
}

static TARGET_PATH: OnceLock<&'static CString> = OnceLock::new();

fn target_path() -> Option<&'static CString> {
    TARGET_PATH.get().copied()
}

/// Raw pointer to the target path C string (for auxv AT_EXECFN).
pub fn target_path_ptr() -> Option<*const c_char> {
    target_path().map(|p| p.as_ptr())
}

/// Diagnostic: describe an address relative to the target image or the host.
pub fn describe_addr(addr: u64) {
    if let Some(t) = TARGET.get() {
        if addr >= t.base && addr < t.end {
            let off = addr - t.base;
            let mut best: Option<&ExportSym> = None;
            for e in &t.exports {
                if e.value <= off && best.is_none_or(|b| e.value > b.value) {
                    best = Some(e);
                }
            }
            match best {
                Some(e) => {
                    rerr!(
                        "addr {addr:#x} in target+{off:#x} ({} + {:#x})",
                        e.name,
                        off - e.value
                    );
                }
                None => rerr!("addr {addr:#x} in target+{off:#x}"),
            }
            return;
        }
    }
    // host module via dladdr
    unsafe {
        let f = sys::dlsym_default("dladdr");
        if let Some(f) = f {
            let f: extern "C" fn(*mut c_void, *mut DlInfo) -> c_int = std::mem::transmute(f);
            let mut info = DlInfo {
                dli_fname: std::ptr::null(),
                dli_fbase: std::ptr::null_mut(),
                dli_sname: std::ptr::null(),
                dli_saddr: std::ptr::null_mut(),
            };
            if f(addr as *mut c_void, &mut info) != 0 {
                let name = if info.dli_fname.is_null() {
                    "?".to_string()
                } else {
                    CStr::from_ptr(info.dli_fname).to_string_lossy().into_owned()
                };
                let sym = if info.dli_sname.is_null() {
                    "?".to_string()
                } else {
                    CStr::from_ptr(info.dli_sname).to_string_lossy().into_owned()
                };
                rerr!(
                    "addr {addr:#x} in host {name} (+{:#x}, {sym})",
                    addr - info.dli_fbase as u64
                );
                return;
            }
        }
    }
    rerr!("addr {addr:#x}: no owning image");
}

/// Diagnostic: per-thread TLS state at crash time.
pub fn roll_call() {
    let tp = sys::get_fs_base();
    match crate::tls::target_block_base() {
        Some(base) => {
            let head = unsafe { std::slice::from_raw_parts(base as *const u8, 16.min(base)) };
            rerr!(
                "tls: TP={tp:#x} target block {base:#x} (head {:02x?})",
                head
            );
        }
        None => rerr!("tls: TP={tp:#x} no target TLS"),
    }
}

pub fn set_target_image(img: &Image) {
    let Some(path) = target_path() else { return };
    let mut exports = img.elf.exports();
    exports.sort_by_key(|e| e.value);
    let dlpi_name: &'static CString = Box::leak(Box::new(CString::new("").unwrap()));
    let t = TargetImage {
        base: img.base,
        end: img.end,
        phdr: img.phdr_addr(),
        phnum: img.elf.phdrs.len() as u16,
        has_tls: img.tls().is_some(),
        path,
        dlpi_name,
        exports,
    };
    let _ = TARGET.set(t);
}

/// Rewrite the host libc's program_invocation_* pointers so both the target
/// and libc-internal diagnostics see the target as the program.
pub fn patch_program_invocation() {
    unsafe {
        if let Some(a) = sys::dlsym_default("program_invocation_name") {
            *(a as *mut *mut c_char) = PROG_NAME.load(Ordering::Relaxed);
        }
        if let Some(a) = sys::dlsym_default("program_invocation_short_name") {
            *(a as *mut *mut c_char) = PROG_SHORT_NAME.load(Ordering::Relaxed);
        }
    }
}

// ---- shim table -----------------------------------------------------------

pub fn shim_for(name: &str) -> Option<usize> {
    let a: usize = match name {
        "__libc_start_main" => shim_libc_start_main as *const () as usize,
        "pthread_create" => shim_pthread_create as *const () as usize,
        "dl_iterate_phdr" => shim_dl_iterate_phdr as *const () as usize,
        "dladdr" => shim_dladdr as *const () as usize,
        "dlsym" => shim_dlsym as *const () as usize,
        "readlink" => shim_readlink as *const () as usize,
        "readlinkat" => shim_readlinkat as *const () as usize,
        "open" | "open64" => shim_open as *const () as usize,
        "openat" | "openat64" => shim_openat as *const () as usize,
        "fopen" | "fopen64" => shim_fopen as *const () as usize,
        "syscall" => shim_syscall as *const () as usize,
        "__tls_get_addr" => shim_tls_get_addr as *const () as usize,
        // data-symbol overrides: the GOT points at our own pointer variables
        "program_invocation_name" => &PROG_NAME as *const _ as usize,
        "program_invocation_short_name" => &PROG_SHORT_NAME as *const _ as usize,
        _ => return None,
    };
    Some(a)
}

// ---- startup --------------------------------------------------------------

/// Constructors/destructors of the target (glibc >= 2.34 removed the crt's
/// __libc_csu_init, so the dynamic loader is responsible for them; elldr
/// plays that role here).
pub struct Ctors {
    pub preinit: Vec<usize>,
    pub init: usize,
    pub init_array: Vec<usize>,
    pub fini: usize,
    pub fini_array: Vec<usize>,
}

static CTORS: OnceLock<Ctors> = OnceLock::new();

pub fn set_ctors(c: Ctors) {
    let _ = CTORS.set(c);
}

extern "C" fn fini_trampoline(_: *mut c_void) {
    if let Some(c) = CTORS.get() {
        for &a in c.fini_array.iter().rev() {
            let f: extern "C" fn() = unsafe { std::mem::transmute(a) };
            f();
        }
        if c.fini != 0 {
            let f: extern "C" fn() = unsafe { std::mem::transmute(c.fini) };
            f();
        }
    }
}

/// Replaces glibc's __libc_start_main: the target's own _start hands us
/// (main, argc, argv, init, fini, rtld_fini, stack_end). Constructors run
/// here (preinit_array, then either the crt's csu_init or DT_INIT +
/// INIT_ARRAY), destructors are registered through __cxa_atexit so exit()
/// runs them, then main is called and the host's exit() leaves the process
/// (stdio flushed, atexit handlers run).
extern "C" fn shim_libc_start_main(
    main: *const c_void,
    argc: c_int,
    argv: *const *const c_char,
    init: *const c_void,
    fini: *const c_void,
    _rtld_fini: *const c_void,
    _stack_end: *const c_void,
) -> ! {
    unsafe {
        let envp = sys::environ as *const *const c_char;
        vlog!("start: main={main:p} argc={argc}");
        let cxa: extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int =
            std::mem::transmute(reals().cxa_atexit);
        if let Some(c) = CTORS.get() {
            let call3 = |a: usize| {
                if a != 0 {
                    let f: extern "C" fn(c_int, *const *const c_char, *const *const c_char) =
                        std::mem::transmute(a);
                    f(argc, argv, envp);
                }
            };
            for &a in &c.preinit {
                call3(a);
            }
            if !init.is_null() {
                let f: extern "C" fn(c_int, *const *const c_char, *const *const c_char) =
                    std::mem::transmute(init);
                f(argc, argv, envp);
                // legacy crt: csu_fini must be registered to run FINI_ARRAY
                if !fini.is_null() {
                    cxa(fini as *mut c_void, std::ptr::null_mut(), std::ptr::null_mut());
                }
            } else {
                call3(c.init);
                for &a in &c.init_array {
                    call3(a);
                }
                if !c.fini_array.is_empty() || c.fini != 0 {
                    cxa(
                        fini_trampoline as *const () as *mut c_void,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                }
            }
            vlog!("start: constructors done");
        } else if !init.is_null() {
            let f: extern "C" fn(c_int, *const *const c_char, *const *const c_char) =
                std::mem::transmute(init);
            f(argc, argv, envp);
        }
        let f: extern "C" fn(c_int, *const *const c_char, *const *const c_char) -> c_int =
            std::mem::transmute(main);
        let ret = f(argc, argv, envp);
        vlog!("start: target main returned {ret}");
        let e: extern "C" fn(c_int) -> ! = std::mem::transmute(reals().exit);
        e(ret);
    }
}

// ---- threads --------------------------------------------------------------

struct StartCtx {
    start: usize,
    arg: *mut c_void,
}

extern "C" fn thread_trampoline(ctx: *mut c_void) -> *mut c_void {
    unsafe {
        let c = Box::from_raw(ctx as *mut StartCtx);
        crate::tls::install_for_current_thread();
        let f: extern "C" fn(*mut c_void) -> *mut c_void = std::mem::transmute(c.start);
        f(c.arg)
    }
}

/// Target-visible pthread_create: wrap the start routine so the new thread
/// gets the target's TLS template before executing any target code.
extern "C" fn shim_pthread_create(
    thread: *mut u64,
    attr: *const c_void,
    start: usize,
    arg: *mut c_void,
) -> c_int {
    if start == 0 {
        return 22; // EINVAL
    }
    let ctx = Box::into_raw(Box::new(StartCtx { start, arg })) as *mut c_void;
    let f: extern "C" fn(
        *mut u64,
        *const c_void,
        extern "C" fn(*mut c_void) -> *mut c_void,
        *mut c_void,
    ) -> c_int = unsafe { std::mem::transmute(reals().pthread_create) };
    let rc = f(thread, attr, thread_trampoline, ctx);
    if rc != 0 {
        unsafe { drop(Box::from_raw(ctx as *mut StartCtx)) };
    } else {
        vlog!("pthread_create: wrapped start={start:#x}");
    }
    rc
}

// ---- dl introspection -----------------------------------------------------

/// dlsym from target code: RTLD_DEFAULT/RTLD_NEXT inside the target must see
/// the target's own exports plus the host's global scope. The host's
/// RTLD_NEXT cannot identify its caller (the target image is not in the host
/// link map) and returns NULL, which Bun then calls (e.g. quick_exit).
extern "C" fn shim_dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    let real: extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
        unsafe { std::mem::transmute(reals().dlsym) };
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let is_next = handle as isize == -1;
    let is_default = handle.is_null();
    if is_next || is_default {
        let sym = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
        if is_default {
            if let Some(t) = TARGET.get() {
                if let Some(e) = t.exports.iter().find(|e| e.name == sym) {
                    let r = resolve_export(t, e);
                    vlog!("dlsym(RTLD_DEFAULT, {sym}) -> {r:p} (target)");
                    return r;
                }
            }
        }
        let r = real(std::ptr::null_mut(), name);
        vlog!(
            "dlsym({}, {sym}) -> {r:p}",
            if is_next { "RTLD_NEXT" } else { "RTLD_DEFAULT" }
        );
        return r;
    }
    real(handle, name)
}

/// Dynamic symbol value: ifunc symbols must run their resolver (ld.so
/// semantics); every other symbol is its address.
fn resolve_export(t: &TargetImage, e: &ExportSym) -> *mut c_void {
    let addr = t.base + e.value;
    if e.stype == 10 {
        let f: extern "C" fn() -> usize = unsafe { std::mem::transmute(addr) };
        return f() as *mut c_void;
    }
    addr as *mut c_void
}

extern "C" fn collect_adds_subs(info: *mut DlPhdrInfo, _size: usize, _data: *mut c_void) -> c_int {
    unsafe {
        ADDS.store((*info).dlpi_adds as usize, Ordering::Relaxed);
        SUBS.store((*info).dlpi_subs as usize, Ordering::Relaxed);
    }
    0
}

fn sample_adds_subs() {
    let f: extern "C" fn(
        extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int,
        *mut c_void,
    ) -> c_int = unsafe { std::mem::transmute(reals().dl_iterate_phdr) };
    f(collect_adds_subs, std::ptr::null_mut());
}

/// The target image is invisible to the host's dynamic linker; report it
/// first (as the main program, dlpi_addr=0 with absolute phdrs), then let the
/// real iteration run. The libgcc/Bun unwinders rely on this to find the
/// target's .eh_frame FDEs.
extern "C" fn shim_dl_iterate_phdr(
    cb: extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int,
    data: *mut c_void,
) -> c_int {
    if let Some(t) = TARGET.get() {
        let mut info = DlPhdrInfo {
            dlpi_addr: 0,
            dlpi_name: t.dlpi_name.as_ptr(),
            dlpi_phdr: t.phdr as *const c_void,
            dlpi_phnum: t.phnum,
            dlpi_adds: ADDS.load(Ordering::Relaxed) as u64,
            dlpi_subs: SUBS.load(Ordering::Relaxed) as u64,
            dlpi_tls_modid: if t.has_tls { 1 } else { 0 },
            dlpi_tls_data: crate::tls::target_block_base().unwrap_or(0) as *mut c_void,
        };
        let r = cb(&mut info, std::mem::size_of::<DlPhdrInfo>(), data);
        if r != 0 {
            return r;
        }
    }
    let f: extern "C" fn(
        extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int,
        *mut c_void,
    ) -> c_int = unsafe { std::mem::transmute(reals().dl_iterate_phdr) };
    f(cb, data)
}

extern "C" fn shim_dladdr(addr: *mut c_void, info: *mut DlInfo) -> c_int {
    if let Some(t) = TARGET.get() {
        let a = addr as u64;
        if a >= t.base && a < t.end {
            let off = a - t.base as u64;
            // nearest preceding defined symbol
            let mut best: Option<&ExportSym> = None;
            for e in &t.exports {
                if e.value <= off && best.is_none_or(|b| e.value > b.value) {
                    best = Some(e);
                }
            }
            let (sname, saddr) = match best {
                Some(e) => (
                    Box::leak(Box::new(
                        CString::new(e.name.as_str()).unwrap_or_default(),
                    ))
                    .as_ptr(),
                    (t.base + e.value) as *mut c_void,
                ),
                None => (std::ptr::null(), std::ptr::null_mut()),
            };
            unsafe {
                *info = DlInfo {
                    dli_fname: t.path.as_ptr(),
                    dli_fbase: t.base as *mut c_void,
                    dli_sname: sname,
                    dli_saddr: saddr,
                };
            }
            return 1;
        }
    }
    let f: extern "C" fn(*mut c_void, *mut DlInfo) -> c_int =
        unsafe { std::mem::transmute(reals().dladdr) };
    f(addr, info)
}

// ---- /proc/self/exe identity ----------------------------------------------

fn is_self_exe_path(path: *const c_char) -> bool {
    if path.is_null() {
        return false;
    }
    let s = unsafe { CStr::from_ptr(path) };
    let b = s.to_bytes();
    if b == b"/proc/self/exe" || b == b"/proc/thread-self/exe" {
        return true;
    }
    if let Some(rest) = b.strip_prefix(b"/proc/") {
        if let Some(pidpart) = rest.strip_suffix(b"/exe") {
            if let Ok(pid) = std::str::from_utf8(pidpart).unwrap_or("").parse::<i32>() {
                return pid == sys::current_pid();
            }
        }
    }
    false
}

fn serve_path(buf: *mut c_char, sz: usize) -> isize {
    let Some(p) = target_path() else { return -22 }; // EINVAL
    let bytes = p.as_bytes_with_nul();
    let n = bytes.len() - 1;
    let n = n.min(sz);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, n);
    }
    n as isize
}

extern "C" fn shim_readlink(path: *const c_char, buf: *mut c_char, sz: usize) -> isize {
    if is_self_exe_path(path) {
        return serve_path(buf, sz);
    }
    let f: extern "C" fn(*const c_char, *mut c_char, usize) -> isize =
        unsafe { std::mem::transmute(reals().readlink) };
    f(path, buf, sz)
}

extern "C" fn shim_readlinkat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    sz: usize,
) -> isize {
    if is_self_exe_path(path) {
        return serve_path(buf, sz);
    }
    let f: extern "C" fn(c_int, *const c_char, *mut c_char, usize) -> isize =
        unsafe { std::mem::transmute(reals().readlinkat) };
    f(dirfd, path, buf, sz)
}

extern "C" fn shim_open(path: *const c_char, flags: c_int, mode: u32) -> c_int {
    let f: extern "C" fn(*const c_char, c_int, u32) -> c_int =
        unsafe { std::mem::transmute(reals().open) };
    if is_self_exe_path(path) {
        if let Some(p) = target_path() {
            return f(p.as_ptr(), flags, mode);
        }
    }
    f(path, flags, mode)
}

extern "C" fn shim_openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: u32,
) -> c_int {
    let f: extern "C" fn(c_int, *const c_char, c_int, u32) -> c_int =
        unsafe { std::mem::transmute(reals().openat) };
    if is_self_exe_path(path) {
        if let Some(p) = target_path() {
            return f(dirfd, p.as_ptr(), flags, mode);
        }
    }
    f(dirfd, path, flags, mode)
}

extern "C" fn shim_fopen(path: *const c_char, mode: *const c_char) -> *mut c_void {
    let f: extern "C" fn(*const c_char, *const c_char) -> *mut c_void =
        unsafe { std::mem::transmute(reals().fopen) };
    if is_self_exe_path(path) {
        if let Some(p) = target_path() {
            return f(p.as_ptr(), mode);
        }
    }
    f(path, mode)
}

// linux syscall numbers
const SYS_OPENAT: c_long = 257;
const SYS_READLINKAT: c_long = 267;
const SYS_STATX: c_long = 332;

/// libc syscall(): redirect the Zen/Zig-style raw wrappers for the
/// /proc/self/exe paths (they bypass readlink/open shims otherwise).
extern "C" fn shim_syscall(
    nr: c_long,
    a1: c_long,
    a2: c_long,
    a3: c_long,
    a4: c_long,
    a5: c_long,
    a6: c_long,
) -> c_long {
    let real: extern "C" fn(c_long, c_long, c_long, c_long, c_long, c_long, c_long) -> c_long =
        unsafe { std::mem::transmute(reals().syscall) };
    match nr {
        SYS_READLINKAT => {
            if is_self_exe_path(a2 as *const c_char) {
                let n = serve_path(a3 as *mut c_char, a4 as usize);
                vlog!("syscall: readlinkat(/proc/self/exe) -> {n}");
                return n as c_long;
            }
        }
        SYS_OPENAT => {
            if is_self_exe_path(a2 as *const c_char) {
                if let Some(p) = target_path() {
                    let r = real(nr, a1, p.as_ptr() as c_long, a3, a4, a5, a6);
                    vlog!("syscall: openat(/proc/self/exe) -> {r}");
                    return r;
                }
            }
        }
        SYS_STATX => {
            if is_self_exe_path(a2 as *const c_char) {
                if let Some(p) = target_path() {
                    return real(nr, a1, p.as_ptr() as c_long, a3, a4, a5, a6);
                }
            }
        }
        _ => {}
    }
    real(nr, a1, a2, a3, a4, a5, a6)
}

/// GD-model TLS is unreachable in a relaxed image; log loudly if it ever is.
extern "C" fn shim_tls_get_addr(ti: *const c_void) -> *mut c_void {
    static WARNED: AtomicUsize = AtomicUsize::new(0);
    if WARNED.swap(1, Ordering::Relaxed) == 0 {
        rerr!("__tls_get_addr called: dynamic TLS in the target is not supported; forwarding");
    }
    let f: extern "C" fn(*const c_void) -> *mut c_void =
        unsafe { std::mem::transmute(reals().tls_get_addr) };
    f(ti)
}
