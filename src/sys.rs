//! Minimal libc bindings (no external crates).

use std::ffi::{c_char, c_int, c_void};

pub const PROT_NONE: c_int = 0x0;
pub const PROT_READ: c_int = 0x1;
pub const PROT_WRITE: c_int = 0x2;
pub const PROT_EXEC: c_int = 0x4;

pub const MAP_PRIVATE: c_int = 0x0002;
pub const MAP_FIXED: c_int = 0x0010;
pub const MAP_ANON: c_int = 0x1000;

pub const RTLD_LAZY: c_int = 0x1;
/// dlfcn.h: RTLD_DEFAULT ((void *)-2)
pub const RTLD_DEFAULT: *mut c_void = -2isize as *mut c_void;

const _SC_PAGESIZE: c_int = 29;

unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int;
    fn sysconf(name: c_int) -> i64;
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, sym: *const c_char) -> *mut c_void;
    fn dlerror() -> *mut c_char;
    fn __error() -> *mut c_int;
    fn pthread_key_create(key: *mut u64, destructor: *const c_void) -> c_int;
    fn pthread_getspecific(key: u64) -> *mut c_void;
    fn pthread_setspecific(key: u64, value: *const c_void) -> c_int;
    pub static environ: *mut *mut c_char;
}

pub fn pthread_key_new() -> Result<u64, String> {
    let mut key = 0u64;
    let r = unsafe { pthread_key_create(&mut key, std::ptr::null()) };
    if r != 0 {
        return Err(format!("pthread_key_create failed ({r})"));
    }
    Ok(key)
}

pub fn tsd_get(key: u64) -> *mut c_void {
    unsafe { pthread_getspecific(key) }
}

pub fn tsd_set(key: u64, value: *mut c_void) {
    unsafe {
        pthread_setspecific(key, value);
    }
}

fn map_failed() -> *mut c_void {
    usize::MAX as *mut c_void
}

pub fn page_size() -> usize {
    let ps = unsafe { sysconf(_SC_PAGESIZE) };
    assert!(ps > 0);
    ps as usize
}

fn errno_str() -> String {
    let e = unsafe { *__error() };
    format!("errno {e}")
}

/// Reserve `len` bytes of inaccessible address space, kernel picks the address.
pub fn reserve(len: usize) -> Result<*mut u8, String> {
    let p = unsafe {
        mmap(
            std::ptr::null_mut(),
            len,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        )
    };
    if p == map_failed() {
        return Err(format!("mmap reserve {len:#x} failed: {}", errno_str()));
    }
    Ok(p as *mut u8)
}

pub fn map_file_fixed(addr: usize, len: usize, prot: c_int, fd: c_int, off: u64) -> Result<(), String> {
    let p = unsafe {
        mmap(
            addr as *mut c_void,
            len,
            prot,
            MAP_PRIVATE | MAP_FIXED,
            fd,
            off as i64,
        )
    };
    if p == map_failed() {
        return Err(format!(
            "mmap file {len:#x} @ {addr:#x} (off {off:#x}) failed: {}",
            errno_str()
        ));
    }
    if p as usize != addr {
        return Err(format!("mmap returned {p:p} instead of {addr:#x}"));
    }
    Ok(())
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
    if p == map_failed() {
        return Err(format!("mmap anon {len:#x} @ {addr:#x} failed: {}", errno_str()));
    }
    if p as usize != addr {
        return Err(format!("mmap returned {p:p} instead of {addr:#x}"));
    }
    Ok(())
}

pub fn protect(addr: usize, len: usize, prot: c_int) -> Result<(), String> {
    let r = unsafe { mprotect(addr as *mut c_void, len, prot) };
    if r != 0 {
        return Err(format!("mprotect {len:#x} @ {addr:#x} -> {prot:#x} failed: {}", errno_str()));
    }
    Ok(())
}

pub fn dlopen_path(path: &str) -> Result<*mut c_void, String> {
    let c = std::ffi::CString::new(path).map_err(|_| format!("bad path {path:?}"))?;
    unsafe { dlerror() };
    let h = unsafe { dlopen(c.as_ptr(), RTLD_LAZY) };
    if h.is_null() {
        let msg = unsafe {
            let e = dlerror();
            if e.is_null() {
                "unknown dlopen error".to_string()
            } else {
                std::ffi::CStr::from_ptr(e).to_string_lossy().into_owned()
            }
        };
        return Err(format!("dlopen({path}) failed: {msg}"));
    }
    Ok(h)
}

/// Symbol names here use the Mach-O spelling (leading underscore), dlsym wants
/// the C spelling without it.
pub fn dlsym_name(handle: *mut c_void, sym: &str) -> Option<usize> {
    let c_name = sym.strip_prefix('_').unwrap_or(sym);
    let c = std::ffi::CString::new(c_name).ok()?;
    unsafe { dlerror() };
    let p = unsafe { dlsym(handle, c.as_ptr()) };
    if p.is_null() {
        // dlerror() may be set even when the pointer is non-null; a null
        // result means not found.
        return None;
    }
    Some(p as usize)
}
