//! Minimal raw libc/POSIX bindings (mmap/dl/pthread/arch_prctl) plus raw-fd
//! logging. Code that runs on target threads must not touch Rust std TLS
//! facilities; this is the only place I/O for it lives.

// Named-constant and binding surface; not every entry is exercised yet.
#![allow(dead_code)]

use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

pub const PROT_NONE: c_int = 0x0;
pub const PROT_READ: c_int = 0x1;
pub const PROT_WRITE: c_int = 0x2;
pub const PROT_EXEC: c_int = 0x4;

pub const MAP_PRIVATE: c_int = 0x02;
pub const MAP_FIXED: c_int = 0x10;
pub const MAP_ANON: c_int = 0x20;
pub const MAP_FIXED_NOREPLACE: c_int = 0x100000;

pub const RTLD_LAZY: c_int = 0x1;
pub const RTLD_NOW: c_int = 0x2;
pub const RTLD_GLOBAL: c_int = 0x100;
/// dlfcn.h on glibc: RTLD_DEFAULT ((void *) 0), RTLD_NEXT ((void *) -1).
pub const RTLD_DEFAULT: *mut c_void = 0 as *mut c_void;

const O_WRONLY: c_int = 0x1;
const O_CREAT: c_int = 0x40;
const O_APPEND: c_int = 0x400;

const ARCH_GET_FS: c_int = 0x1003;
const _SC_PAGESIZE: c_int = 30;

// getauxval types
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;
pub const AT_SYSINFO_EHDR: u64 = 33;

unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int;
    fn sysconf(name: c_int) -> c_long;
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, sym: *const c_char) -> *mut c_void;
    fn dlvsym(handle: *mut c_void, sym: *const c_char, version: *const c_char) -> *mut c_void;
    fn dlerror() -> *mut c_char;
    fn __errno_location() -> *mut c_int;
    fn strerror(e: c_int) -> *mut c_char;
    fn arch_prctl(code: c_int, addr: *mut u64) -> c_int;
    fn getauxval(t: u64) -> u64;
    fn getpid() -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn open(path: *const c_char, flags: c_int, mode: u32) -> c_int;
    pub fn exit(code: c_int) -> !;
    pub fn _exit(code: c_int) -> !;
    pub static environ: *mut *mut c_char;
}

// pthread shims: pthread_t is unsigned long on x86_64; pthread_attr_t is
// 56 bytes and pointer-aligned.
unsafe extern "C" {
    fn pthread_create(
        thread: *mut u64,
        attr: *const c_void,
        start: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
    fn pthread_join(thread: u64, retval: *mut *mut c_void) -> c_int;
    fn pthread_self() -> u64;
    fn pthread_attr_init(attr: *mut c_void) -> c_int;
    fn pthread_attr_destroy(attr: *mut c_void) -> c_int;
    fn pthread_attr_setstacksize(attr: *mut c_void, size: usize) -> c_int;
    fn pthread_getattr_np(thread: u64, attr: *mut c_void) -> c_int;
    fn pthread_attr_getstack(
        attr: *const c_void,
        addr: *mut *mut c_void,
        size: *mut usize,
    ) -> c_int;
}

pub fn errno() -> c_int {
    unsafe { *__errno_location() }
}

pub fn errno_str(e: c_int) -> String {
    unsafe { CStr::from_ptr(strerror(e)).to_string_lossy().into_owned() }
}

pub fn page_size() -> usize {
    static CACHE: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let v = unsafe { sysconf(_SC_PAGESIZE) } as usize;
    CACHE.store(v, Ordering::Relaxed);
    v
}

const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;

/// Reserve `len` bytes at `addr` exactly: anonymous PROT_NONE with
/// MAP_FIXED_NOREPLACE, so an unexpected occupant is an error, not a clobber.
pub fn reserve_fixed(addr: usize, len: usize) -> Result<(), String> {
    let p = unsafe {
        mmap(
            addr as *mut c_void,
            len,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if p == addr as *mut c_void {
        Ok(())
    } else {
        if p != MAP_FAILED {
            unsafe { munmap(p, len) };
        }
        Err(format!(
            "reserve {:#x}+{:#x} failed: {} ({})",
            addr,
            len,
            errno_str(errno()),
            errno()
        ))
    }
}

pub fn map_file_fixed(
    addr: usize,
    len: usize,
    prot: c_int,
    fd: c_int,
    offset: i64,
) -> Result<(), String> {
    let p = unsafe {
        mmap(
            addr as *mut c_void,
            len,
            prot,
            MAP_PRIVATE | MAP_FIXED,
            fd,
            offset,
        )
    };
    if p == addr as *mut c_void {
        Ok(())
    } else {
        Err(format!(
            "mmap file {:#x}+{:#x} (off {:#x}) failed: {} ({})",
            addr,
            len,
            offset,
            errno_str(errno()),
            errno()
        ))
    }
}

pub fn map_anon_fixed(addr: usize, len: usize, prot: c_int) -> Result<(), String> {
    let p = unsafe {
        mmap(
            addr as *mut c_void,
            len,
            prot,
            MAP_PRIVATE | MAP_ANON | MAP_FIXED,
            -1,
            0,
        )
    };
    if p == addr as *mut c_void {
        Ok(())
    } else {
        Err(format!(
            "mmap anon {:#x}+{:#x} failed: {} ({})",
            addr,
            len,
            errno_str(errno()),
            errno()
        ))
    }
}

/// Read-only private mapping of a whole file; leaked on purpose.
pub fn map_file_ro(fd: c_int, len: usize) -> Result<&'static [u8], String> {
    let p = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ, MAP_PRIVATE, fd, 0) };
    if p == MAP_FAILED {
        return Err(format!(
            "mmap file ({} bytes) failed: {} ({})",
            len,
            errno_str(errno()),
            errno()
        ));
    }
    Ok(unsafe { std::slice::from_raw_parts(p as *const u8, len) })
}

pub fn dlopen_path(path: &str, mode: c_int) -> Result<*mut c_void, String> {
    unsafe { dlerror() };
    let c = CString::new(path).map_err(|_| format!("bad path {path}"))?;
    let h = unsafe { dlopen(c.as_ptr(), mode) };
    if h.is_null() {
        Err(dlerror_text())
    } else {
        Ok(h)
    }
}

pub fn dlerror_text() -> String {
    unsafe {
        let e = dlerror();
        if e.is_null() {
            "unknown dl error".to_string()
        } else {
            CStr::from_ptr(e).to_string_lossy().into_owned()
        }
    }
}

pub fn dlsym_default(name: &str) -> Option<usize> {
    let c = CString::new(name).ok()?;
    let p = unsafe { dlsym(RTLD_DEFAULT, c.as_ptr()) };
    if p.is_null() { None } else { Some(p as usize) }
}

pub fn dlvsym_default(name: &str, version: &str) -> Option<usize> {
    let c = CString::new(name).ok()?;
    let v = CString::new(version).ok()?;
    let p = unsafe { dlvsym(RTLD_DEFAULT, c.as_ptr(), v.as_ptr()) };
    if p.is_null() { None } else { Some(p as usize) }
}

pub fn get_fs_base() -> u64 {
    let mut tp: u64 = 0;
    unsafe { arch_prctl(ARCH_GET_FS, &mut tp) };
    tp
}

pub fn auxval(t: u64) -> u64 {
    unsafe { getauxval(t) }
}

pub fn current_pid() -> i32 {
    unsafe { getpid() }
}

// ---- pthread helpers ------------------------------------------------------

/// Opaque storage for glibc pthread_attr_t (56 bytes, 8-aligned).
#[repr(C, align(8))]
pub struct PthreadAttr([u64; 8]);

impl PthreadAttr {
    pub fn new() -> Result<Self, String> {
        let mut a = PthreadAttr([0; 8]);
        let rc = unsafe { pthread_attr_init(&mut a.0 as *mut _ as *mut c_void) };
        if rc != 0 {
            return Err(format!("pthread_attr_init failed: {rc}"));
        }
        Ok(a)
    }

    pub fn set_stacksize(&mut self, size: usize) -> Result<(), String> {
        let rc = unsafe { pthread_attr_setstacksize(&mut self.0 as *mut _ as *mut c_void, size) };
        if rc != 0 {
            return Err(format!("pthread_attr_setstacksize({size:#x}) failed: {rc}"));
        }
        Ok(())
    }

    pub fn as_ptr(&self) -> *const c_void {
        &self.0 as *const _ as *const c_void
    }
}

impl Drop for PthreadAttr {
    fn drop(&mut self) {
        unsafe { pthread_attr_destroy(&mut self.0 as *mut _ as *mut c_void) };
    }
}

pub fn spawn_thread(
    stack_size: usize,
    start: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
) -> Result<u64, String> {
    let mut attr = PthreadAttr::new()?;
    attr.set_stacksize(stack_size)?;
    let mut tid: u64 = 0;
    let rc = unsafe { pthread_create(&mut tid, attr.as_ptr(), start, arg) };
    if rc != 0 {
        return Err(format!("pthread_create failed: {rc}"));
    }
    Ok(tid)
}

pub fn join_thread(tid: u64) {
    unsafe { pthread_join(tid, std::ptr::null_mut()) };
}

/// (stack_base, stack_size) of the calling thread.
pub fn current_stack_bounds() -> Result<(usize, usize), String> {
    let mut attr = PthreadAttr([0; 8]);
    let rc = unsafe {
        pthread_getattr_np(
            pthread_self(),
            &mut attr.0 as *mut _ as *mut c_void,
        )
    };
    if rc != 0 {
        return Err(format!("pthread_getattr_np failed: {rc}"));
    }
    let mut base: *mut c_void = std::ptr::null_mut();
    let mut size: usize = 0;
    let rc = unsafe {
        pthread_attr_getstack(
            &attr.0 as *const _ as *const c_void,
            &mut base,
            &mut size,
        )
    };
    if rc != 0 {
        return Err(format!("pthread_attr_getstack failed: {rc}"));
    }
    Ok((base as usize, size))
}

// ---- raw fd logging -------------------------------------------------------

static LOG_FD: AtomicI32 = AtomicI32::new(-1);

/// ELLDR_LOG=<path> redirects all raw diagnostics to that file (append).
pub fn init_logging() {
    if let Ok(p) = std::env::var("ELLDR_LOG") {
        if let Ok(c) = CString::new(p) {
            let fd = unsafe { open(c.as_ptr(), O_WRONLY | O_CREAT | O_APPEND, 0o600) };
            if fd >= 0 {
                LOG_FD.store(fd, Ordering::Relaxed);
            }
        }
    }
}

/// Thread-safe, TLS-free diagnostics output (std's stderr is off-limits on
/// target threads).
pub fn raw_stderr(s: &str) {
    let fd = LOG_FD.load(Ordering::Relaxed);
    let fd = if fd >= 0 { fd } else { 2 };
    unsafe {
        write(fd, s.as_ptr() as *const c_void, s.len());
    }
}
