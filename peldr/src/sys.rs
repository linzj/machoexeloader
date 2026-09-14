//! Minimal Win32 / ntdll bindings and TEB/PEB access (no external crates).

use std::ffi::{c_char, c_void};

pub type Handle = *mut c_void;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

pub const INFINITE: u32 = 0xFFFF_FFFF;

unsafe extern "system" {
    pub fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;
    pub fn VirtualProtect(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
    pub fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32;

    pub fn LoadLibraryA(lpLibFileName: *const c_char) -> Handle;
    pub fn GetModuleHandleA(lpModuleName: *const c_char) -> Handle;
    pub fn GetProcAddress(hModule: Handle, lpProcName: *const c_char) -> *mut c_void;
    pub fn GetModuleHandleExW(dwFlags: u32, lpModuleName: *const u16, phModule: *mut Handle) -> i32;

    pub fn GetSystemDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    pub fn GetWindowsDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    pub fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: Handle,
    ) -> Handle;
    pub fn WideCharToMultiByte(
        CodePage: u32,
        dwFlags: u32,
        lpWideCharStr: *const u16,
        cchWideChar: i32,
        lpMultiByteStr: *mut u8,
        cbMultiByte: i32,
        lpDefaultChar: *const u8,
        lpUsedDefaultChar: *mut i32,
    ) -> i32;

    pub fn CreateThread(
        lpThreadAttributes: *mut c_void,
        dwStackSize: usize,
        lpStartAddress: Option<unsafe extern "system" fn(*mut c_void) -> u32>,
        lpParameter: *mut c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
    ) -> Handle;
    pub fn WaitForSingleObject(hHandle: Handle, dwMilliseconds: u32) -> u32;
    pub fn GetExitCodeThread(hThread: Handle, lpExitCode: *mut u32) -> i32;

    pub fn GetLastError() -> u32;
    pub fn GetCurrentThreadId() -> u32;
    pub fn GetStdHandle(nStdHandle: u32) -> Handle;
    pub fn GetConsoleMode(hConsoleHandle: Handle, lpMode: *mut u32) -> i32;
    pub fn GetFileType(hFile: Handle) -> u32;
    pub fn GetNumberOfConsoleInputEvents(hConsoleInput: Handle, lpcNumberOfEvents: *mut u32) -> i32;
    pub fn Sleep(dwMilliseconds: u32);
    pub fn WriteFile(
        hFile: Handle,
        lpBuffer: *const u8,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;

    pub fn SetUnhandledExceptionFilter(
        lpTopLevelExceptionFilter: Option<
            unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        >,
    ) -> *mut c_void;

    pub fn GetCurrentProcessId() -> u32;
    pub fn GetCurrentProcess() -> Handle;
    pub fn CloseHandle(hObject: Handle) -> i32;
    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> Handle;
    pub fn Thread32First(hSnapshot: Handle, lpte: *mut ThreadEntry32) -> i32;
    pub fn Thread32Next(hSnapshot: Handle, lpte: *mut ThreadEntry32) -> i32;
    pub fn OpenThread(dwDesiredAccess: u32, bInheritHandle: i32, dwThreadId: u32) -> Handle;
}

#[repr(C)]
pub struct ThreadEntry32 {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_thread_id: u32,
    pub th32_owner_process_id: u32,
    pub tp_base_pri: i32,
    pub cnt_priority_class: u32,
    pub cnt_priority: u32,
}

/// (tid, Win32 start address) for every thread of the current process.
/// Used by diagnostics: threads we never bootstrapped (and thus never gave a
/// target TLS array to) stand out with a start address in target code.
pub fn thread_audit() -> Vec<(u32, usize)> {
    let mut v = Vec::new();
    const TH32CS_SNAPTHREAD: u32 = 0x4;
    const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0040;
    const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap as isize == -1 {
            return v;
        }
        let pid = GetCurrentProcessId();
        let ntq = ntdll_proc("NtQueryInformationThread");
        let mut te: ThreadEntry32 = std::mem::zeroed();
        te.dw_size = std::mem::size_of::<ThreadEntry32>() as u32;
        if Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32_owner_process_id == pid {
                    let h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, te.th32_thread_id);
                    let mut start: usize = 0;
                    if !h.is_null() {
                        if let Some(f) = ntq {
                            let f: unsafe extern "system" fn(Handle, u32, *mut c_void, u32, *mut u32) -> i32 =
                                std::mem::transmute(f);
                            let mut ret = 0u32;
                            f(
                                h,
                                THREAD_QUERY_SET_WIN32_START_ADDRESS,
                                &mut start as *mut usize as *mut c_void,
                                std::mem::size_of::<usize>() as u32,
                                &mut ret,
                            );
                        }
                        CloseHandle(h);
                    }
                    v.push((te.th32_thread_id, start));
                }
                if Thread32Next(snap, &mut te) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    v
}

#[repr(C)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: *mut ExceptionRecord,
    pub exception_address: *mut c_void,
    pub number_parameters: u32,
    pub _pad: u32,
    pub exception_information: [usize; 15],
}

#[repr(C)]
pub struct ExceptionPointers {
    pub exception_record: *mut ExceptionRecord,
    pub context_record: *mut c_void,
}

pub fn page_size() -> usize {
    4096
}

/// Hard process exit: the target's own exit()/atexit handlers have already
/// run (its CRT exit path precedes its ExitProcess call), so skip ntdll's
/// user-mode teardown entirely -- it walks TEB TLS state that a manually
/// mapped image only fakes. Exit code and flushed output are preserved.
pub fn terminate_self(code: u32) -> ! {
    let gcp = get_proc(kernel32(), "GetCurrentProcess").expect("GetCurrentProcess");
    let gcp: extern "system" fn() -> Handle = unsafe { std::mem::transmute(gcp) };
    let term = get_proc(kernel32(), "TerminateProcess").expect("TerminateProcess");
    let term: unsafe extern "system" fn(Handle, u32) -> i32 = unsafe { std::mem::transmute(term) };
    unsafe {
        term(gcp(), code);
    }
    std::process::abort();
}

/// Raw stderr write that must work on any thread, under any TLS state.
/// With PELDR_LOG=<path> set, diagnostics go to that file instead, so the
/// process stdio stays untouched (TUI targets check tty-ness).
static LOG_HANDLE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Call once from the main thread before running the target.
pub fn init_logging() {
    let Some(p) = std::env::var_os("PELDR_LOG") else { return };
    let w = to_wide(&p.to_string_lossy());
    let f = unsafe {
        CreateFileW(
            w.as_ptr(),
            0x4,       // FILE_APPEND_DATA
            0x1 | 0x2, // FILE_SHARE_READ | FILE_SHARE_WRITE
            std::ptr::null_mut(),
            0x4,       // OPEN_ALWAYS
            0x80,      // FILE_ATTRIBUTE_NORMAL
            std::ptr::null_mut(),
        )
    };
    if f as isize != -1 {
        LOG_HANDLE.store(f as usize, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn raw_stderr(msg: &str) {
    let mut written = 0u32;
    let log = LOG_HANDLE.load(std::sync::atomic::Ordering::Relaxed);
    if log != 0 {
        unsafe {
            WriteFile(log as Handle, msg.as_ptr(), msg.len() as u32, &mut written, std::ptr::null_mut());
        }
        return;
    }
    let h = unsafe { GetStdHandle(0xFFFF_FFF4) }; // STD_ERROR_HANDLE
    if h.is_null() {
        return;
    }
    unsafe {
        WriteFile(h, msg.as_ptr(), msg.len() as u32, &mut written, std::ptr::null_mut());
    }
}

pub fn round_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

pub fn last_error(what: &str) -> String {
    format!("{what} failed (GetLastError {})", unsafe { GetLastError() })
}

/// Reserve `len` bytes of address space at `addr` (0 = kernel picks).
pub fn reserve(addr: usize, len: usize) -> Option<*mut u8> {
    let p = unsafe { VirtualAlloc(addr as *mut c_void, len, MEM_RESERVE, PAGE_NOACCESS) };
    if p.is_null() { None } else { Some(p as *mut u8) }
}

/// Commit a range inside a reservation as read/write.
pub fn commit(addr: usize, len: usize) -> Result<(), String> {
    let p = unsafe { VirtualAlloc(addr as *mut c_void, len, MEM_COMMIT, PAGE_READWRITE) };
    if p.is_null() {
        return Err(last_error(&format!("VirtualAlloc commit {len:#x} @ {addr:#x}")));
    }
    Ok(())
}

pub fn protect(addr: usize, len: usize, prot: u32) -> Result<(), String> {
    protect_get(addr, len, prot).map(|_| ())
}

/// Like `protect` but returns the previous protection.
pub fn protect_get(addr: usize, len: usize, prot: u32) -> Result<u32, String> {
    let mut old = 0u32;
    let r = unsafe { VirtualProtect(addr as *mut c_void, len, prot, &mut old) };
    if r == 0 {
        return Err(last_error(&format!("VirtualProtect {len:#x} @ {addr:#x} -> {prot:#x}")));
    }
    Ok(old)
}

pub fn release(addr: usize, len: usize) {
    unsafe {
        VirtualFree(addr as *mut c_void, len, MEM_RELEASE);
    }
}

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert a NUL-terminated wide string to the ANSI code page (NUL appended).
pub fn wide_to_ansi_nul(w: &[u16]) -> Vec<u8> {
    let chars = w.len().saturating_sub(1) as i32;
    let n = unsafe {
        WideCharToMultiByte(0, 0, w.as_ptr(), chars, std::ptr::null_mut(), 0, std::ptr::null(), std::ptr::null_mut())
    };
    if n <= 0 {
        return vec![0];
    }
    let mut out = vec![0u8; n as usize + 1];
    unsafe {
        WideCharToMultiByte(0, 0, w.as_ptr(), chars, out.as_mut_ptr(), n, std::ptr::null(), std::ptr::null_mut());
    }
    out
}

pub fn load_library_a(name: &str) -> Result<Handle, String> {
    let c = std::ffi::CString::new(name).map_err(|_| format!("bad library name {name:?}"))?;
    let h = unsafe { LoadLibraryA(c.as_ptr()) };
    if h.is_null() {
        return Err(last_error(&format!("LoadLibraryA({name})")));
    }
    Ok(h)
}

pub fn get_proc(module: Handle, name: &str) -> Option<usize> {
    let c = std::ffi::CString::new(name).ok()?;
    let p = unsafe { GetProcAddress(module, c.as_ptr()) };
    if p.is_null() { None } else { Some(p as usize) }
}

pub fn get_proc_ordinal(module: Handle, ordinal: u16) -> Option<usize> {
    // MAKEINTRESOURCEA: the low 16 bits hold the ordinal.
    let p = unsafe { GetProcAddress(module, ordinal as usize as *const c_char) };
    if p.is_null() { None } else { Some(p as usize) }
}

fn dir_buf(f: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Option<String> {
    let mut buf = vec![0u16; 260];
    let n = unsafe { f(buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        None
    } else {
        Some(String::from_utf16_lossy(&buf[..n as usize]))
    }
}

/// Module handle for an address inside a loaded module (works for the
/// process image itself).
pub fn module_from_address(addr: usize) -> Handle {
    let mut h: Handle = std::ptr::null_mut();
    // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | UNCHANGED_REFCOUNT
    unsafe {
        GetModuleHandleExW(0x4 | 0x2, addr as *const u16, &mut h);
    }
    h
}

/// %SystemRoot% (e.g. "C:\Windows").
pub fn windows_dir() -> Option<String> {
    dir_buf(GetWindowsDirectoryW)
}

/// The system directory (e.g. "C:\Windows\System32").
pub fn system_dir() -> Option<String> {
    dir_buf(GetSystemDirectoryW)
}

pub fn kernel32() -> Handle {
    static mut HANDLE: Handle = std::ptr::null_mut();
    // Single-threaded during setup; shims run after and only read.
    unsafe {
        if HANDLE.is_null() {
            HANDLE = GetModuleHandleA(c"kernel32.dll".as_ptr());
        }
        HANDLE
    }
}

pub fn ntdll_proc(name: &str) -> Option<usize> {
    let h = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr()) };
    if h.is_null() { None } else { get_proc(h, name) }
}

/// Register `count` RUNTIME_FUNCTION entries (at `table`) for `image_base`
/// with the OS unwinder. Required for SEH/C++ exceptions in manually mapped
/// images: ntdll does not know about us otherwise.
pub fn rtl_add_function_table(table: usize, count: u32, image_base: u64) -> Result<(), String> {
    let f = ntdll_proc("RtlAddFunctionTable")
        .ok_or("ntdll!RtlAddFunctionTable not found")?;
    let f: unsafe extern "system" fn(*const u8, u32, u64) -> u8 = unsafe { std::mem::transmute(f) };
    let ok = unsafe { f(table as *const u8, count, image_base) };
    if ok == 0 {
        return Err(format!(
            "RtlAddFunctionTable({count} entries @ {table:#x}) failed (GetLastError {})",
            unsafe { GetLastError() }
        ));
    }
    Ok(())
}

// ---- TEB / PEB -------------------------------------------------------------

pub fn teb() -> usize {
    unsafe {
        let t: usize;
        std::arch::asm!("mov {}, gs:[0x30]", out(reg) t, options(nostack, preserves_flags));
        t
    }
}

const TEB_TLS_ARRAY: usize = 0x58;
const TEB_PEB: usize = 0x60;

pub fn peb() -> usize {
    unsafe { *((teb() + TEB_PEB) as *const usize) }
}

/// Pointer to TEB->ThreadLocalStoragePointer (array of per-module TLS blocks).
pub fn tls_array_for(teb: usize) -> *mut usize {
    unsafe { *((teb + TEB_TLS_ARRAY) as *const *mut usize) }
}

pub fn set_tls_array_for(teb: usize, arr: *mut usize) {
    unsafe {
        *((teb + TEB_TLS_ARRAY) as *mut *mut usize) = arr;
    }
}
