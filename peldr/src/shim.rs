//! Runtime shims injected into the target's IAT (the PE analogue of mldr's
//! shim_lookup): imports of the target are resolved to these instead of the
//! host functions, so we can keep the illusion that the target is the main
//! image, hand out module handles for self-mapped DLLs, and keep module TLS
//! consistent across threads created through CreateThread/_beginthreadex.

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::image::ImageKind;
use crate::loader::Registry;
use crate::pe::{ExportEntry, ImportName};
use crate::sys::{self, Handle};
use crate::vlog;

pub struct ViewImage {
    pub base: usize,
    pub size: u32,
    pub name: String,
    pub path: Option<PathBuf>,
    pub exports: HashMap<String, ExportEntry>,
    pub exports_ord: HashMap<u32, ExportEntry>,
}

pub struct View {
    /// Self-mapped images; extended by runtime LoadLibrary self-mapping.
    pub images: Mutex<Vec<ViewImage>>,
    pub main_dir: std::path::PathBuf,
    pub extra_dirs: Vec<std::path::PathBuf>,
}

static VIEW: OnceLock<View> = OnceLock::new();
/// Serializes runtime self-mapping of DLLs.
static RUNTIME_LOAD_LOCK: Mutex<()> = Mutex::new(());
static TARGET_PATH_W: OnceLock<Vec<u16>> = OnceLock::new();
static TARGET_PATH_A: OnceLock<Vec<u8>> = OnceLock::new();
static CMD_LINE_W: OnceLock<Vec<u16>> = OnceLock::new();
static CMD_LINE_A: OnceLock<Vec<u8>> = OnceLock::new();

static REAL_LOAD_LIBRARY_W: AtomicUsize = AtomicUsize::new(0);
static REAL_LOAD_LIBRARY_A: AtomicUsize = AtomicUsize::new(0);
static REAL_LOAD_LIBRARY_EX_W: AtomicUsize = AtomicUsize::new(0);
static REAL_LOAD_LIBRARY_EX_A: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_PROC_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_MODULE_HANDLE_W: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_MODULE_HANDLE_A: AtomicUsize = AtomicUsize::new(0);
static REAL_FREE_LIBRARY: AtomicUsize = AtomicUsize::new(0);
static REAL_CREATE_THREAD: AtomicUsize = AtomicUsize::new(0);
static REAL_BEGIN_THREAD_EX: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_MODULE_FILE_NAME_W: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_MODULE_FILE_NAME_A: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_COMMAND_LINE_W: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_COMMAND_LINE_A: AtomicUsize = AtomicUsize::new(0);
static REAL_WSA_STARTUP: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_HOST_NAME_W: AtomicUsize = AtomicUsize::new(0);
static REAL_WGETMAINARGS: AtomicUsize = AtomicUsize::new(0);
static REAL_EXIT_PROCESS: AtomicUsize = AtomicUsize::new(0);
static REAL_EXIT_THREAD: AtomicUsize = AtomicUsize::new(0);
static REAL_TERMINATE_PROCESS: AtomicUsize = AtomicUsize::new(0);
static REAL_GET_CURRENT_PROCESS: AtomicUsize = AtomicUsize::new(0);

static GET_PROC_CACHE: Mutex<Option<HashMap<(usize, String), Option<usize>>>> = Mutex::new(None);

/// Resolve the "real" kernel32/ucrtbase routines the shims fall back to.
/// Called once before import binding.
pub fn init_reals() {
    let k32 = sys::kernel32();
    let set = |slot: &AtomicUsize, name: &str| {
        if let Some(p) = sys::get_proc(k32, name) {
            slot.store(p, Ordering::Relaxed);
        }
    };
    set(&REAL_LOAD_LIBRARY_W, "LoadLibraryW");
    set(&REAL_LOAD_LIBRARY_A, "LoadLibraryA");
    set(&REAL_LOAD_LIBRARY_EX_W, "LoadLibraryExW");
    set(&REAL_LOAD_LIBRARY_EX_A, "LoadLibraryExA");
    set(&REAL_GET_PROC_ADDRESS, "GetProcAddress");
    set(&REAL_GET_MODULE_HANDLE_W, "GetModuleHandleW");
    set(&REAL_GET_MODULE_HANDLE_A, "GetModuleHandleA");
    set(&REAL_FREE_LIBRARY, "FreeLibrary");
    set(&REAL_CREATE_THREAD, "CreateThread");
    set(&REAL_GET_MODULE_FILE_NAME_W, "GetModuleFileNameW");
    set(&REAL_GET_MODULE_FILE_NAME_A, "GetModuleFileNameA");
    set(&REAL_GET_COMMAND_LINE_W, "GetCommandLineW");
    set(&REAL_GET_COMMAND_LINE_A, "GetCommandLineA");
    set(&REAL_EXIT_PROCESS, "ExitProcess");
    set(&REAL_EXIT_THREAD, "ExitThread");
    set(&REAL_TERMINATE_PROCESS, "TerminateProcess");
    set(&REAL_GET_CURRENT_PROCESS, "GetCurrentProcess");
    if let Ok(ucrt) = sys::load_library_a("ucrtbase.dll") {
        if let Some(p) = sys::get_proc(ucrt, "_beginthreadex") {
            REAL_BEGIN_THREAD_EX.store(p, Ordering::Relaxed);
        }
    }
    if let Ok(msvcrt) = sys::load_library_a("msvcrt.dll") {
        if let Some(p) = sys::get_proc(msvcrt, "__wgetmainargs") {
            REAL_WGETMAINARGS.store(p, Ordering::Relaxed);
        }
    }
    if let Ok(ws2) = sys::load_library_a("ws2_32.dll") {
        if let Some(p) = sys::get_proc(ws2, "WSAStartup") {
            REAL_WSA_STARTUP.store(p, Ordering::Relaxed);
        }
        if let Some(p) = sys::get_proc(ws2, "GetHostNameW") {
            REAL_GET_HOST_NAME_W.store(p, Ordering::Relaxed);
        }
    }
    vlog!(
        "shim reals: llw={:#x} gpa={:#x} ct={:#x} bte={:#x}",
        REAL_LOAD_LIBRARY_W.load(Ordering::Relaxed),
        REAL_GET_PROC_ADDRESS.load(Ordering::Relaxed),
        REAL_CREATE_THREAD.load(Ordering::Relaxed),
        REAL_BEGIN_THREAD_EX.load(Ordering::Relaxed)
    );
}

/// Freeze the loader state the shims consult at runtime. Only self-mapped
/// images are visible here: host (bridged) modules are handled by the real
/// kernel32 functions.
pub fn install(reg: &Registry, extra_dirs: &[String]) {
    let images = reg
        .images
        .iter()
        .filter(|im| im.kind != ImageKind::Bridged)
        .map(|im| ViewImage {
            base: im.base,
            size: im.pe().size_of_image,
            name: im.name.clone(),
            path: im.path.clone(),
            exports: im.exports.clone(),
            exports_ord: im.exports_ord.clone(),
        })
        .collect();
    let main_dir = reg.images[reg.main]
        .path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    let _ = VIEW.set(View {
        images: Mutex::new(images),
        main_dir,
        extra_dirs: extra_dirs.iter().map(std::path::PathBuf::from).collect(),
    });
}

pub fn set_target_path(path: &std::path::Path) {
    let s = path.display().to_string();
    let _ = TARGET_PATH_W.set(sys::to_wide(&s));
    let _ = TARGET_PATH_A.set(s.into_bytes().into_iter().chain(Some(0)).collect());
}

/// Store the fabricated command line. The PEB patch and the GetCommandLine
/// shims share these buffers: kernelbase caches whatever it saw first, so we
/// serve the target ourselves. Returns (wide ptr, length in bytes w/o NUL).
pub fn set_command_line(cmd: &str) -> (*mut u16, u16) {
    let w = sys::to_wide(cmd);
    let byte_len = (w.len() - 1) * 2;
    let _ = CMD_LINE_A.set(sys::wide_to_ansi_nul(&w));
    let _ = CMD_LINE_W.set(w);
    let p = CMD_LINE_W.get().unwrap().as_ptr() as *mut u16;
    (p, byte_len as u16)
}

fn view() -> &'static View {
    VIEW.get().expect("shim view not installed")
}

/// PELDR_TRACE_AV=1: log every first-chance exception (RIP + backtrace with
/// image+offset classification) without handling it. Bun/JSC install their
/// own VEH and swallow segfaults, so this is the only way to see them.
pub fn install_av_tracer() {
    static ONCE: OnceLock<()> = OnceLock::new();
    if std::env::var_os("PELDR_TRACE_AV").is_none() {
        return;
    }
    ONCE.get_or_init(|| {
        let f: extern "system" fn(u32, *const u8) -> *mut c_void = {
            let p = sys::get_proc(sys::kernel32(), "AddVectoredExceptionHandler")
                .expect("AddVectoredExceptionHandler");
            unsafe { std::mem::transmute(p) }
        };
        let h = f(1, av_tracer as *const () as *const u8);
        vlog!("av tracer installed: {h:p}");
    });
}

fn describe_addr(addr: usize) -> String {
    if let Some(v) = VIEW.get() {
        if let Ok(images) = v.images.lock() {
            for im in images.iter() {
                if addr >= im.base && addr < im.base + im.size as usize {
                    return format!("{}+{:#x}", im.name, addr - im.base);
                }
            }
        }
    }
    format!("{addr:#x}")
}

unsafe extern "system" fn av_tracer(info: *mut sys::ExceptionPointers) -> i32 {
    let mut out = String::new();
    unsafe {
        let er = (*info).exception_record;
        let code = (*er).exception_code;
        // Skip breakpoints/DBG single-steps.
        if code != 0x8000_0005 {
            let addr = (*er).exception_address as usize;
            let rip = if !(*info).context_record.is_null() {
                let ctx = (*info).context_record as *const u8;
                *(ctx.add(0xF8) as *const usize)
            } else {
                addr
            };
            let mut frames = [0usize; 24];
            let f: extern "system" fn(u32, u32, *mut *mut c_void, *mut u32) -> u32 = {
                let p = sys::get_proc(sys::kernel32(), "RtlCaptureStackBackTrace")
                    .or_else(|| sys::ntdll_proc("RtlCaptureStackBackTrace"))
                    .unwrap_or(0);
                std::mem::transmute(p)
            };
            let n = if f as usize != 0 {
                f(0, frames.len() as u32, frames.as_mut_ptr() as *mut *mut c_void, std::ptr::null_mut())
            } else {
                0
            };
            out.push_str(&format!(
                "peldr: av: code {code:#010x} addr {} rip {} read={} accessed={}\n",
                describe_addr(addr),
                describe_addr(rip),
                (*er).exception_information[0],
                (*er).exception_information[1]
            ));
            if !(*info).context_record.is_null() {
                let ctx = (*info).context_record as *const u8;
                let rd = |off: usize| *(ctx.add(off) as *const usize);
                out.push_str(&format!(
                    "peldr: av:   rax={:#x} rcx={:#x} rdx={:#x} rbx={:#x} rsp={:#x} rbp={:#x} rsi={:#x} rdi={:#x}\n",
                    rd(0x78), rd(0x80), rd(0x88), rd(0x90), rd(0x98), rd(0xA0), rd(0xA8), rd(0xB0)
                ));
                out.push_str(&format!(
                    "peldr: av:   r8={:#x} r9={:#x} r10={:#x} r11={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}\n",
                    rd(0xB8), rd(0xC0), rd(0xC8), rd(0xD0), rd(0xD8), rd(0xE0), rd(0xE8), rd(0xF0)
                ));
                let code_bytes = std::slice::from_raw_parts(rip as *const u8, 64);
                out.push_str(&format!("peldr: av:   @rip: {code_bytes:02x?}\n"));
                let before = std::slice::from_raw_parts((rip - 80) as *const u8, 80);
                out.push_str(&format!("peldr: av:   pre: {before:02x?}\n"));
                let rsp = rd(0x98);
                let mut line = String::from("peldr: av:   stack:");
                for i in 0..48usize {
                    let v = *(rsp as *const usize).add(i);
                    line.push_str(&format!(" {v:x}"));
                }
                out.push_str(&line);
                out.push('\n');
            }
            for (i, fr) in frames[..n as usize].iter().enumerate() {
                out.push_str(&format!("peldr: av:   #{i:<2} {}\n", describe_addr(*fr)));
            }
        }
    }
    sys::raw_stderr(&out);
    0 // EXCEPTION_CONTINUE_SEARCH
}

pub fn view_if_installed() -> Option<&'static View> {
    VIEW.get()
}

fn find_self(name: &str) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    let file = lower.rsplit(['\\', '/']).next().unwrap_or(&lower).to_string();
    let v = view();
    let images = v.images.lock().ok()?;
    if let Some(i) = images.iter().position(|im| im.name == file) {
        return Some(i);
    }
    // Path-based match (canonicalize when possible).
    if lower.contains(['\\', '/']) {
        if let Ok(p) = std::fs::canonicalize(name) {
            if let Some(i) = images
                .iter()
                .position(|im| im.path.as_deref() == Some(p.as_path()))
            {
                return Some(i);
            }
        }
    }
    None
}

fn base_index(h: Handle) -> Option<usize> {
    let b = h as usize;
    let v = view();
    let images = v.images.lock().ok()?;
    images.iter().position(|im| im.base == b)
}

fn view_base(i: usize) -> usize {
    view().images.lock().unwrap()[i].base
}

fn wide_to_string(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 && len < 32768 {
            len += 1;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, len)))
    }
}

// ---- shim bodies -----------------------------------------------------------

/// Resolve a LoadLibrary request: already self-mapped image, or a user DLL
/// found next to the target which we map ourselves on the spot.
fn self_or_runtime(name: &str) -> Option<usize> {
    if let Some(i) = find_self(name) {
        let base = view_base(i);
        vlog!("shim: LoadLibrary({name}) -> self-mapped {base:#x}");
        return Some(base);
    }
    match runtime_load_self_dll(name) {
        Ok(Some(base)) => {
            vlog!("shim: LoadLibrary({name}) -> runtime self-map {base:#x}");
            Some(base)
        }
        Ok(None) => None,
        Err(e) => {
            crate::rerr!("runtime self-map of {name} failed: {e}");
            None
        }
    }
}

extern "system" fn shim_load_library_w(name: *const u16) -> Handle {
    if let Some(s) = wide_to_string(name) {
        if let Some(base) = self_or_runtime(&s) {
            return base as Handle;
        }
    }
    let f: unsafe extern "system" fn(*const u16) -> Handle =
        unsafe { std::mem::transmute(REAL_LOAD_LIBRARY_W.load(Ordering::Relaxed)) };
    let h = unsafe { f(name) };
    if !h.is_null() {
        crate::tls::on_host_module_load();
    }
    h
}

extern "system" fn shim_load_library_a(name: *const c_char) -> Handle {
    if !name.is_null() {
        let s = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
        if let Some(base) = self_or_runtime(&s) {
            return base as Handle;
        }
    }
    let f: unsafe extern "system" fn(*const c_char) -> Handle =
        unsafe { std::mem::transmute(REAL_LOAD_LIBRARY_A.load(Ordering::Relaxed)) };
    let h = unsafe { f(name) };
    if !h.is_null() {
        crate::tls::on_host_module_load();
    }
    h
}

extern "system" fn shim_load_library_ex_w(
    name: *const u16,
    file: Handle,
    flags: u32,
) -> Handle {
    if file.is_null() && flags == 0 {
        if let Some(s) = wide_to_string(name) {
            if let Some(base) = self_or_runtime(&s) {
                return base as Handle;
            }
        }
    }
    let f: unsafe extern "system" fn(*const u16, Handle, u32) -> Handle =
        unsafe { std::mem::transmute(REAL_LOAD_LIBRARY_EX_W.load(Ordering::Relaxed)) };
    let h = unsafe { f(name, file, flags) };
    if !h.is_null() {
        crate::tls::on_host_module_load();
    }
    h
}

extern "system" fn shim_load_library_ex_a(
    name: *const c_char,
    file: Handle,
    flags: u32,
) -> Handle {
    if file.is_null() && flags == 0 && !name.is_null() {
        let s = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
        if let Some(base) = self_or_runtime(&s) {
            return base as Handle;
        }
    }
    let f: unsafe extern "system" fn(*const c_char, Handle, u32) -> Handle =
        unsafe { std::mem::transmute(REAL_LOAD_LIBRARY_EX_A.load(Ordering::Relaxed)) };
    let h = unsafe { f(name, file, flags) };
    if !h.is_null() {
        crate::tls::on_host_module_load();
    }
    h
}

/// Map a user DLL at runtime (the dynamic counterpart of load-time self
/// mapping): parse, map, bind its imports, register unwind tables.
fn runtime_load_self_dll(name: &str) -> Result<Option<usize>, String> {
    let _g = RUNTIME_LOAD_LOCK
        .lock()
        .map_err(|_| "runtime load lock poisoned".to_string())?;
    runtime_load_inner(name)
}

/// Same, assuming RUNTIME_LOAD_LOCK is already held (recursion for deps).
fn runtime_load_inner(name: &str) -> Result<Option<usize>, String> {
    if let Some(i) = find_self(name) {
        return Ok(Some(view_base(i)));
    }
    let v = view();
    let Some(path) = resolve_self_candidate(name, &v.main_dir, &v.extra_dirs) else {
        return Ok(None);
    };
    {
        let images = v.images.lock().unwrap();
        if let Some(im) = images.iter().find(|im| im.path.as_deref() == Some(path.as_path())) {
            return Ok(Some(im.base));
        }
    }
    let pe = crate::pe::Pe::parse_file(&path)?;
    if !pe.is_dll() {
        return Ok(None);
    }
    vlog!("shim: runtime self-mapping {}", path.display());
    let img_name = crate::loader::file_name_lower(&path);
    let img = crate::image::Image::map(pe, ImageKind::SelfDll, img_name.clone(), false)?;
    if let Some(t) = &img.tls {
        if t.index_rva != 0 || t.template_size > 0 {
            crate::rerr!("runtime DLL {img_name} has a TLS directory; its thread-locals are not supported");
        }
    }
    bind_runtime_image(&img)?;
    img.reprotect()?;
    if let Some((addr, count)) = img.pdata_addr() {
        let _ = sys::rtl_add_function_table(addr, count, img.base as u64);
    }
    let base = img.base;
    v.images.lock().unwrap().push(ViewImage {
        base,
        size: img.pe().size_of_image,
        name: img_name,
        path: Some(path),
        exports: img.exports.clone(),
        exports_ord: img.exports_ord.clone(),
    });
    Ok(Some(base))
}

fn resolve_self_candidate(name: &str, main_dir: &Path, extra: &[PathBuf]) -> Option<PathBuf> {
    if name.contains(['\\', '/']) {
        let p = Path::new(name);
        if p.is_file() && !p.parent().map(crate::loader::is_under_windows_dir).unwrap_or(true) {
            return crate::loader::canon(p);
        }
        return None;
    }
    for d in std::iter::once(main_dir.to_path_buf()).chain(extra.iter().cloned()) {
        if d.as_os_str().is_empty() || crate::loader::is_under_windows_dir(&d) {
            continue;
        }
        let cand = d.join(name);
        if cand.is_file() {
            if let Some(p) = crate::loader::canon(&cand) {
                return Some(p);
            }
        }
    }
    None
}

/// Bind one runtime-mapped image's IAT against the view's exports, the shim
/// table, or the host (LoadLibrary/GetProcAddress bridge).
fn bind_runtime_image(img: &crate::image::Image) -> Result<(), String> {
    let pe = img.pe();
    for dll in pe.imports()? {
        let self_i = find_self(&dll.name);
        for (fi, func) in dll.funcs.iter().enumerate() {
            let addr = if let Some(a) = shim_for(&dll.name, func) {
                a
            } else if let Some(i) = self_i {
                lookup_in_image(i, func, 0).ok_or_else(|| {
                    format!("{}: import {}!{} not found", img.name, dll.name, func_name(func))
                })?
            } else if runtime_load_inner(&dll.name)?.is_some() {
                // A user DLL next to the target (recursively mapped now).
                let i = find_self(&dll.name).ok_or_else(|| {
                    format!("{}: import {} not found after mapping", img.name, dll.name)
                })?;
                lookup_in_image(i, func, 0).ok_or_else(|| {
                    format!("{}: import {}!{} not found", img.name, dll.name, func_name(func))
                })?
            } else {
                let h = sys::load_library_a(&dll.name)?;
                match func {
                    ImportName::Name(n) => sys::get_proc(h, n),
                    ImportName::Ordinal(o) => sys::get_proc_ordinal(h, *o),
                }
                .ok_or_else(|| {
                    format!("{}: import {}!{} not found in host", img.name, dll.name, func_name(func))
                })?
            };
            let slot = img.base + dll.iat_rva as usize + fi * 8;
            unsafe {
                *(slot as *mut u64) = addr as u64;
            }
        }
    }
    Ok(())
}

fn func_name(f: &ImportName) -> String {
    match f {
        ImportName::Name(n) => n.clone(),
        ImportName::Ordinal(o) => format!("#{o}"),
    }
}

fn lookup_in_image(i: usize, func: &ImportName, depth: usize) -> Option<usize> {
    if depth > 8 {
        return None;
    }
    let (base, entry) = {
        let v = view();
        let images = v.images.lock().ok()?;
        let im = images.get(i)?;
        let entry = match func {
            ImportName::Name(n) => im.exports.get(n).cloned()?,
            ImportName::Ordinal(o) => im.exports_ord.get(&(*o as u32)).cloned()?,
        };
        (im.base, entry)
    };
    match entry {
        ExportEntry::Rva(rva) => Some(base + rva as usize),
        ExportEntry::Forwarder(fwd) => {
            let (dll, name) = fwd.rsplit_once('.')?;
            if let Some(j) = find_self(dll) {
                let o = name.parse::<u16>().ok().map(ImportName::Ordinal);
                let n = ImportName::Name(name.to_string());
                lookup_in_image(j, &n, depth + 1)
                    .or_else(|| o.and_then(|o| lookup_in_image(j, &o, depth + 1)))
            } else {
                // Host forwarder: go straight to kernel32's GetProcAddress.
                let h = sys::load_library_a(dll).ok()?;
                sys::get_proc(h, name)
            }
        }
    }
}

extern "system" fn shim_get_proc_address(hmod: Handle, name: *const c_char) -> *mut c_void {
    if let Some(i) = base_index(hmod) {
        let p = name as usize;
        let r = if p <= 0xFFFF {
            lookup_in_image(i, &ImportName::Ordinal(p as u16), 0)
        } else if name.is_null() {
            None
        } else {
            let s = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
            lookup_in_image(i, &ImportName::Name(s), 0)
        };
        return r
            .map(|a| a as *mut c_void)
            .unwrap_or(std::ptr::null_mut());
    }
    // Fall through to the host, with a cache (negative results included).
    let key = if name as usize <= 0xFFFF {
        (hmod as usize, format!("#{}", name as usize))
    } else if name.is_null() {
        return std::ptr::null_mut();
    } else {
        let s = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
        (hmod as usize, s)
    };
    let mut guard = GET_PROC_CACHE.lock().unwrap();
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some(&c) = cache.get(&key) {
        return c.unwrap_or(0) as *mut c_void;
    }
    let f: unsafe extern "system" fn(Handle, *const c_char) -> *mut c_void =
        unsafe { std::mem::transmute(REAL_GET_PROC_ADDRESS.load(Ordering::Relaxed)) };
    let p = unsafe { f(hmod, name) };
    cache.insert(key, if p.is_null() { None } else { Some(p as usize) });
    p
}

extern "system" fn shim_get_module_handle_w(name: *const u16) -> Handle {
    if let Some(s) = wide_to_string(name) {
        if let Some(i) = find_self(&s) {
            return view_base(i) as Handle;
        }
    }
    let f: unsafe extern "system" fn(*const u16) -> Handle =
        unsafe { std::mem::transmute(REAL_GET_MODULE_HANDLE_W.load(Ordering::Relaxed)) };
    unsafe { f(name) }
}

extern "system" fn shim_get_module_handle_a(name: *const c_char) -> Handle {
    if !name.is_null() {
        let s = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
        if let Some(i) = find_self(&s) {
            return view_base(i) as Handle;
        }
    }
    let f: unsafe extern "system" fn(*const c_char) -> Handle =
        unsafe { std::mem::transmute(REAL_GET_MODULE_HANDLE_A.load(Ordering::Relaxed)) };
    unsafe { f(name) }
}

extern "system" fn shim_free_library(h: Handle) -> i32 {
    if base_index(h).is_some() {
        return 1;
    }
    let f: unsafe extern "system" fn(Handle) -> i32 =
        unsafe { std::mem::transmute(REAL_FREE_LIBRARY.load(Ordering::Relaxed)) };
    unsafe { f(h) }
}

struct ThreadStart {
    start: usize,
    param: *mut c_void,
}

unsafe extern "system" fn thread_bootstrap(p: *mut c_void) -> u32 {
    vlog!("shim: thread start (bootstrap entered)");
    let ts = unsafe { Box::from_raw(p as *mut ThreadStart) };
    if let Err(e) = crate::tls::attach_current_thread() {
        crate::rerr!("TLS setup failed on new thread: {e}");
    }
    vlog!("shim: thread attached, calling target start {:#x}", ts.start);
    let f: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(ts.start) };
    let r = unsafe { f(ts.param) };
    // Hand ntdll back a normal-looking TLS array before this thread dies.
    crate::tls::restore_current_thread_array();
    vlog!("shim: target start returned {r}");
    r
}

extern "system" fn shim_create_thread(
    attrs: *mut c_void,
    stack: usize,
    start: Option<unsafe extern "system" fn(*mut c_void) -> u32>,
    param: *mut c_void,
    flags: u32,
    tid: *mut u32,
) -> Handle {
    let f: unsafe extern "system" fn(
        *mut c_void,
        usize,
        Option<unsafe extern "system" fn(*mut c_void) -> u32>,
        *mut c_void,
        u32,
        *mut u32,
    ) -> Handle = unsafe { std::mem::transmute(REAL_CREATE_THREAD.load(Ordering::Relaxed)) };
    match start {
        None => unsafe { f(attrs, stack, None, param, flags, tid) },
        Some(s) => {
            vlog!("shim: CreateThread(start {:#x}) wrapped", s as usize);
            let ts = Box::into_raw(Box::new(ThreadStart {
                start: s as usize,
                param,
            }));
            unsafe { f(attrs, stack, Some(thread_bootstrap), ts as *mut c_void, flags, tid) }
        }
    }
}

extern "system" fn shim_beginthreadex(
    security: *mut c_void,
    stack: u32,
    start: usize,
    arg: *mut c_void,
    flags: u32,
    tid: *mut u32,
) -> usize {
    let f: unsafe extern "system" fn(*mut c_void, u32, usize, *mut c_void, u32, *mut u32) -> usize =
        unsafe { std::mem::transmute(REAL_BEGIN_THREAD_EX.load(Ordering::Relaxed)) };
    if start == 0 {
        return unsafe { f(security, stack, start, arg, flags, tid) };
    }
    let ts = Box::into_raw(Box::new(ThreadStart {
        start,
        param: arg,
    }));
    unsafe { f(security, stack, thread_bootstrap as *const () as usize, ts as *mut c_void, flags, tid) }
}

extern "system" fn shim_get_module_file_name_w(h: Handle, buf: *mut u16, size: u32) -> u32 {
    if h.is_null() || base_index(h).is_some() {
        if let Some(w) = TARGET_PATH_W.get() {
            return write_wide(w, buf, size);
        }
    }
    let f: unsafe extern "system" fn(Handle, *mut u16, u32) -> u32 =
        unsafe { std::mem::transmute(REAL_GET_MODULE_FILE_NAME_W.load(Ordering::Relaxed)) };
    unsafe { f(h, buf, size) }
}

extern "system" fn shim_get_module_file_name_a(h: Handle, buf: *mut u8, size: u32) -> u32 {
    if h.is_null() || base_index(h).is_some() {
        if let Some(a) = TARGET_PATH_A.get() {
            return write_ansi(a, buf, size);
        }
    }
    let f: unsafe extern "system" fn(Handle, *mut u8, u32) -> u32 =
        unsafe { std::mem::transmute(REAL_GET_MODULE_FILE_NAME_A.load(Ordering::Relaxed)) };
    unsafe { f(h, buf, size) }
}

/// Diagnostic: PELDR_TRACE_EXIT=1 routes the target's exit()/exit variants
/// through logging stubs so we can see where a silent exit comes from.
fn trace_exit() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("PELDR_TRACE_EXIT").is_some())
}

#[unsafe(naked)]
extern "system" fn shim_trace_exit(_code: i32) -> ! {
    std::arch::naked_asm!(
        "mov rdx, [rsp]",
        "jmp {inner}",
        inner = sym shim_trace_exit_inner,
    )
}

unsafe extern "system" fn shim_trace_exit_inner(code: i32, ret: usize) -> ! {
    let mut where_ = format!("{ret:#x}");
    if let Some(v) = view_if_installed() {
        if let Ok(images) = v.images.lock() {
            for im in images.iter() {
                if ret >= im.base && ret < im.base + im.size as usize {
                    where_ = format!("{} +{:#x}", im.name, ret - im.base);
                }
            }
        }
    }
    crate::rerr!("trace: target called exit({code}) from {where_}");
    sys::terminate_self(code as u32)
}

extern "system" fn shim_trace_amsg_exit(code: i32) -> ! {
    crate::rerr!("trace: target called _amsg_exit({code})");
    sys::terminate_self(code as u32)
}

fn trace_sock() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("PELDR_TRACE_SOCK").is_some())
}

extern "system" fn shim_wgetmainargs(
    argc: *mut i32,
    argv: *mut *mut *mut u16,
    envp: *mut *mut *mut u16,
    wildcard: i32,
    startupinfo: *mut c_void,
) -> i32 {
    let f: unsafe extern "system" fn(
        *mut i32,
        *mut *mut *mut u16,
        *mut *mut *mut u16,
        i32,
        *mut c_void,
    ) -> i32 = unsafe { std::mem::transmute(REAL_WGETMAINARGS.load(Ordering::Relaxed)) };
    let r = unsafe { f(argc, argv, envp, wildcard, startupinfo) };
    let mut out = String::new();
    unsafe {
        out.push_str(&format!(
            "peldr: trace: __wgetmainargs(wild={wildcard}) -> {r} argc={}\n",
            if argc.is_null() { -1 } else { *argc }
        ));
        if r == 0 && !argc.is_null() && !(*argv).is_null() {
            for i in 0..(*argc).clamp(0, 16) as usize {
                let p = *(*argv).add(i);
                if p.is_null() {
                    break;
                }
                let mut n = 0usize;
                while *p.add(n) != 0 && n < 512 {
                    n += 1;
                }
                out.push_str(&format!(
                    "peldr: trace:   argv[{i}] = {:?}\n",
                    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
                ));
            }
        }
    }
    sys::raw_stderr(&out);
    r
}

extern "system" fn shim_wsa_startup(version: u16, data: *mut c_void) -> i32 {
    let f: unsafe extern "system" fn(u16, *mut c_void) -> i32 =
        unsafe { std::mem::transmute(REAL_WSA_STARTUP.load(Ordering::Relaxed)) };
    let r = unsafe { f(version, data) };
    crate::rerr!("trace: WSAStartup({version:#x}, {data:p}) -> {r}");
    r
}

extern "system" fn shim_get_host_name_w(buf: *mut u16, len: i32) -> i32 {
    let f: unsafe extern "system" fn(*mut u16, i32) -> i32 =
        unsafe { std::mem::transmute(REAL_GET_HOST_NAME_W.load(Ordering::Relaxed)) };
    let r = unsafe { f(buf, len) };
    let gle = unsafe { sys::GetLastError() };
    crate::rerr!("trace: GetHostNameW({buf:p}, {len}) -> {r} (gle {gle})");
    r
}

extern "system" fn shim_get_command_line_w() -> *const u16 {
    if let Some(w) = CMD_LINE_W.get() {
        return w.as_ptr();
    }
    let f: extern "system" fn() -> *const u16 =
        unsafe { std::mem::transmute(REAL_GET_COMMAND_LINE_W.load(Ordering::Relaxed)) };
    f()
}

extern "system" fn shim_get_command_line_a() -> *const u8 {
    if let Some(a) = CMD_LINE_A.get() {
        return a.as_ptr();
    }
    let f: extern "system" fn() -> *const u8 =
        unsafe { std::mem::transmute(REAL_GET_COMMAND_LINE_A.load(Ordering::Relaxed)) };
    f()
}

// Explicit process exit: the target's exit() has already run its atexit
// handlers; terminate hard so ntdll's teardown never walks TEB TLS state
// that only looks like a loader-loaded process.
extern "system" fn shim_exit_process(code: u32) -> ! {
    sys::terminate_self(code)
}

extern "system" fn shim_exit_thread(code: u32) -> ! {
    crate::tls::restore_current_thread_array();
    let f: unsafe extern "system" fn(u32) -> ! =
        unsafe { std::mem::transmute(REAL_EXIT_THREAD.load(Ordering::Relaxed)) };
    unsafe { f(code) }
}

extern "system" fn shim_terminate_process(h: Handle, code: u32) -> i32 {
    let gcp: extern "system" fn() -> Handle =
        unsafe { std::mem::transmute(REAL_GET_CURRENT_PROCESS.load(Ordering::Relaxed)) };
    if h == gcp() {
        crate::tls::restore_current_thread_array();
    }
    let f: unsafe extern "system" fn(Handle, u32) -> i32 =
        unsafe { std::mem::transmute(REAL_TERMINATE_PROCESS.load(Ordering::Relaxed)) };
    unsafe { f(h, code) }
}

/// Route GetCommandLineA/W inside the host CRT DLLs through our shims.
/// The target's CRT (msvcrt/ucrtbase) calls those internally, not through
/// the target's own IAT, and kernelbase caches whatever it saw first --
/// often the loader's own command line.
pub fn patch_host_crt_command_line() {
    let targets: [(&str, usize); 2] = [
        ("GetCommandLineW", shim_get_command_line_w as *const () as usize),
        ("GetCommandLineA", shim_get_command_line_a as *const () as usize),
    ];
    for dll in ["msvcrt.dll", "ucrtbase.dll"] {
        if let Ok(h) = sys::load_library_a(dll) {
            unsafe {
                patch_host_module_iat(h as usize, &targets);
            }
            // The legacy CRT caches the command line in its own globals at
            // load time (_acmdln/_wcmdln are exported data symbols).
            let plain = h as usize;
            unsafe {
                if let Some(p) = sys::get_proc(plain as Handle, "_acmdln") {
                    if let Some(a) = CMD_LINE_A.get() {
                        *(p as *mut *const u8) = a.as_ptr();
                        vlog!("shim: patched host {dll}!_acmdln");
                    }
                }
                if let Some(p) = sys::get_proc(plain as Handle, "_wcmdln") {
                    if let Some(w) = CMD_LINE_W.get() {
                        *(p as *mut *const u16) = w.as_ptr();
                        vlog!("shim: patched host {dll}!_wcmdln");
                    }
                }
            }
        }
    }
}

/// Patch one host module's IAT entries on the live (mapped) image.
unsafe fn patch_host_module_iat(base: usize, targets: &[(&str, usize)]) {
    let cstr = |at: usize| -> String {
        let mut n = 0usize;
        while n < 512 && unsafe { *(at as *const u8).add(n) } != 0 {
            n += 1;
        }
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(at as *const u8, n)).into_owned() }
    };
    unsafe {
        if base == 0 || *(base as *const u16) != 0x5A4D {
            return;
        }
        let e = *((base + 0x3C) as *const u32) as usize;
        let opt = base + e + 24;
        if *(opt as *const u16) != 0x020B {
            return;
        }
        let ndir = *((opt + 108) as *const u32);
        if ndir < 2 {
            return;
        }
        let imp_rva = *((opt + 112 + 8) as *const u32) as usize;
        if imp_rva == 0 {
            return;
        }
        let mut desc = base + imp_rva;
        for _ in 0..512 {
            let ilt = *((desc) as *const u32) as usize;
            let name_rva = *((desc + 12) as *const u32) as usize;
            let iat = *((desc + 16) as *const u32) as usize;
            if ilt == 0 && name_rva == 0 && iat == 0 {
                break;
            }
            let dll = cstr(base + name_rva).to_ascii_lowercase();
            let core = dll.starts_with("kernel32")
                || dll.starts_with("kernelbase")
                || dll.starts_with("api-ms-win-core");
            if core {
                let thunks = if ilt != 0 { ilt } else { iat };
                for i in 0..4096usize {
                    let t = *((base + thunks + i * 8) as *const u64);
                    if t == 0 {
                        break;
                    }
                    if t & 0x8000_0000_0000_0000 == 0 {
                        let name = cstr(base + (t as u32 as usize) + 2);
                        for (want, addr) in targets {
                            if name == *want {
                                let slot = base + iat + i * 8;
                                let page = slot & !(sys::page_size() - 1);
                                if let Ok(old) =
                                    sys::protect_get(page, sys::page_size(), sys::PAGE_READWRITE)
                                {
                                    *(slot as *mut u64) = *addr as u64;
                                    let _ = sys::protect(page, sys::page_size(), old);
                                    vlog!(
                                        "shim: patched host {dll}!{name} at {slot:#x} -> {addr:#x}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            desc += 20;
        }
    }
}

fn write_wide(src: &[u16], buf: *mut u16, size: u32) -> u32 {
    // src is NUL-terminated; drop the NUL for the copy count.
    let chars = src.len().saturating_sub(1);
    if buf.is_null() || size == 0 {
        return 0;
    }
    let n = chars.min(size as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), buf, n);
        *buf.add(n) = 0;
    }
    n as u32
}

fn write_ansi(src: &[u8], buf: *mut u8, size: u32) -> u32 {
    let chars = src.len().saturating_sub(1);
    if buf.is_null() || size == 0 {
        return 0;
    }
    let n = chars.min(size as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), buf, n);
        *buf.add(n) = 0;
    }
    n as u32
}

/// Choose the shim for an imported (dll, function), if any.
pub fn shim_for(dll: &str, func: &ImportName) -> Option<usize> {
    let name = match func {
        ImportName::Name(n) => n.as_str(),
        ImportName::Ordinal(_) => return None,
    };
    let d = dll.to_ascii_lowercase();
    let core = d.starts_with("kernel32")
        || d.starts_with("kernelbase")
        || d.starts_with("api-ms-win-core");
    let crt = d.starts_with("ucrtbase")
        || d.starts_with("api-ms-win-crt")
        || d.starts_with("msvcrt");
    let have = |slot: &AtomicUsize| slot.load(Ordering::Relaxed) != 0;
    let cast = |f: *const ()| Some(f as usize);
    if trace_exit() {
        match name {
            "exit" | "_exit" => return cast(shim_trace_exit as *const ()),
            "_amsg_exit" => return cast(shim_trace_amsg_exit as *const ()),
            "__wgetmainargs" if have(&REAL_WGETMAINARGS) => {
                return cast(shim_wgetmainargs as *const ())
            }
            _ => {}
        }
    }
    if trace_sock() && d.starts_with("ws2_32") && have(&REAL_WSA_STARTUP) && have(&REAL_GET_HOST_NAME_W) {
        match name {
            "WSAStartup" => return cast(shim_wsa_startup as *const ()),
            "GetHostNameW" => return cast(shim_get_host_name_w as *const ()),
            _ => {}
        }
    }
    if core {
        match name {
            "LoadLibraryW" if have(&REAL_LOAD_LIBRARY_W) => cast(shim_load_library_w as *const ()),
            "LoadLibraryA" if have(&REAL_LOAD_LIBRARY_A) => cast(shim_load_library_a as *const ()),
            "LoadLibraryExW" if have(&REAL_LOAD_LIBRARY_EX_W) => {
                cast(shim_load_library_ex_w as *const ())
            }
            "LoadLibraryExA" if have(&REAL_LOAD_LIBRARY_EX_A) => {
                cast(shim_load_library_ex_a as *const ())
            }
            "GetProcAddress" if have(&REAL_GET_PROC_ADDRESS) => {
                cast(shim_get_proc_address as *const ())
            }
            "GetModuleHandleW" if have(&REAL_GET_MODULE_HANDLE_W) => {
                cast(shim_get_module_handle_w as *const ())
            }
            "GetModuleHandleA" if have(&REAL_GET_MODULE_HANDLE_A) => {
                cast(shim_get_module_handle_a as *const ())
            }
            "FreeLibrary" if have(&REAL_FREE_LIBRARY) => cast(shim_free_library as *const ()),
            "CreateThread" if have(&REAL_CREATE_THREAD) => cast(shim_create_thread as *const ()),
            "GetModuleFileNameW" if have(&REAL_GET_MODULE_FILE_NAME_W) => {
                cast(shim_get_module_file_name_w as *const ())
            }
            "GetModuleFileNameA" if have(&REAL_GET_MODULE_FILE_NAME_A) => {
                cast(shim_get_module_file_name_a as *const ())
            }
            "GetCommandLineW" if have(&REAL_GET_COMMAND_LINE_W) => {
                cast(shim_get_command_line_w as *const ())
            }
            "GetCommandLineA" if have(&REAL_GET_COMMAND_LINE_A) => {
                cast(shim_get_command_line_a as *const ())
            }
            "ExitProcess" if have(&REAL_EXIT_PROCESS) => cast(shim_exit_process as *const ()),
            "ExitThread" if have(&REAL_EXIT_THREAD) => cast(shim_exit_thread as *const ()),
            "TerminateProcess" if have(&REAL_TERMINATE_PROCESS) => {
                cast(shim_terminate_process as *const ())
            }
            _ => None,
        }
    } else if crt {
        match name {
            "_beginthreadex" if have(&REAL_BEGIN_THREAD_EX) => {
                cast(shim_beginthreadex as *const ())
            }
            _ => None,
        }
    } else {
        None
    }
}
