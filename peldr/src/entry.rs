//! PEB patching, command line construction and the jump to the target entry.

use std::ffi::c_void;
use std::path::Path;

use crate::loader::Registry;
use crate::sys;
use crate::vlog;

struct EntryStart {
    entry: usize,
}

/// PEB offsets (x64).
const PEB_IMAGE_BASE: usize = 0x10;
const PEB_LDR: usize = 0x18;
const PEB_PROCESS_PARAMS: usize = 0x20;
const PARAMS_IMAGE_PATH_NAME: usize = 0x60;
const PARAMS_COMMAND_LINE: usize = 0x70;
const LDR_IN_LOAD_ORDER: usize = 0x10;
const LDR_LINKS: usize = 0x0;
const LDR_FULL_DLL_NAME: usize = 0x48;
const LDR_BASE_DLL_NAME: usize = 0x58;

pub fn run_target(reg: &Registry, argv: Vec<String>) -> ! {
    let img = &reg.images[reg.main];
    let pe = img.pe();
    let entry = img.addr_of(pe.entry_rva);
    let path = img.path.clone().expect("main image has a path");
    let stack = (pe.stack_reserve as usize).max(8 * 1024 * 1024);

    patch_peb(img.base, pe.size_of_image, &path, &argv);
    crate::shim::set_target_path(&path);

    vlog!(
        "entry point {entry:#x}, stack reserve {stack:#x} (declared {:#x}/{:#x})",
        pe.stack_reserve,
        pe.stack_commit
    );
    install_crash_filter();
    install_panic_hook();
    crate::shim::patch_host_crt_command_line();
    crate::shim::install_av_tracer();
    start_input_probe();
    let param = Box::into_raw(Box::new(EntryStart { entry })) as *mut c_void;
    std::io::Write::flush(&mut std::io::stdout()).ok();
    std::io::Write::flush(&mut std::io::stderr()).ok();

    let h = unsafe {
        sys::CreateThread(
            std::ptr::null_mut(),
            stack,
            Some(start_thread),
            param,
            0,
            std::ptr::null_mut(),
        )
    };
    if h.is_null() {
        eprintln!("peldr: failed to create target thread ({})", unsafe { sys::GetLastError() });
        std::process::exit(127);
    }
    unsafe {
        sys::WaitForSingleObject(h, sys::INFINITE);
    }
    let mut code = 127u32;
    unsafe {
        sys::GetExitCodeThread(h, &mut code);
    }
    // Only reached when the target thread returned from the entry point
    // without calling ExitProcess; CRT-based targets exit() instead.
    sys::terminate_self(code);
}

unsafe extern "system" fn start_thread(p: *mut c_void) -> u32 {
    let es = unsafe { Box::from_raw(p as *mut EntryStart) };
    if let Err(e) = crate::tls::attach_current_thread() {
        crate::rerr!("TLS setup failed on target thread: {e}");
        return 127;
    }
    crate::tls::run_callbacks();
    // A real process does not deliver DLL_THREAD_ATTACH to the exe/loader
    // for its initial thread. Diagnose whether the extra pass confuses
    // per-thread runtime init (PELDR_NO_MT_ATTACH skips it).
    static SKIP_MT_ATTACH: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let skip = *SKIP_MT_ATTACH.get_or_init(|| std::env::var_os("PELDR_NO_MT_ATTACH").is_some());
    if !skip {
        crate::tls::run_thread_attach_callbacks();
    }
    vlog!("jumping to target entry {:#x}", es.entry);
    let f: unsafe extern "system" fn() -> i32 = unsafe { std::mem::transmute(es.entry) };
    let ret = unsafe { f() };
    crate::tls::restore_current_thread_array();
    vlog!("target entry returned {ret}");
    ret as u32
}

/// Verbose-only watchdog: report the stdin handle's nature and pending console
/// input count every couple of seconds, plus the shim event counters and the
/// tracked-thread inventory every 10 seconds. A "keys do nothing" report can
/// then be split into "input never reaches the console" vs "wait/callback
/// broken" vs "target stopped consuming events", and the last counter
/// snapshot narrows down where execution stalled.
extern "system" fn input_probe_thread(_param: *mut c_void) -> u32 {
    // A raw thread: Rust std threads are unsafe here because the loader's
    // `_tls_index` was moved to slot C, so extend this thread's TLS first.
    if let Err(e) = crate::tls::extend_current_loader_thread() {
        crate::rerr!("input probe TLS setup failed: {e}");
    }
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // (DWORD)-10
    let h = unsafe { sys::GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0u32;
    let cm = unsafe { sys::GetConsoleMode(h, &mut mode) };
    let ft = unsafe { sys::GetFileType(h) };
    vlog!("input probe: stdin {h:p} consolemode ok={cm} mode={mode:#x} filetype={ft}");
    let mut tick = 0u32;
    let mut last_reads = 0usize;
    let mut frozen_ticks = 0u32;
    loop {
        let mut n = 0u32;
        let ok = unsafe { sys::GetNumberOfConsoleInputEvents(h, &mut n) };
        vlog!("input probe: pending events ok={ok} n={n}");
        // Freeze detection: console events are waiting, but the target has
        // not read any for ~12s. Dump the console-driver state once.
        let reads = crate::diag::CON_READS.load(std::sync::atomic::Ordering::Relaxed);
        if ok != 0 && n > 0 && reads == last_reads && reads > 0 {
            frozen_ticks += 1;
        } else {
            frozen_ticks = 0;
        }
        if frozen_ticks == 6 {
            dump_console_freeze_state(n);
        }
        last_reads = reads;
        tick += 1;
        if tick % 5 == 0 {
            vlog!("watchdog: {}", crate::diag::snapshot());
            let threads = crate::tls::snapshot_threads();
            let list: Vec<String> = threads
                .iter()
                .map(|(tid, t, r)| {
                    format!("{tid}{}{}", if *t { "/T" } else { "" }, if *r { "/R" } else { "" })
                })
                .collect();
            vlog!(
                "watchdog: {} tracked thread(s): {}",
                list.len(),
                list.join(" ")
            );
        }
        unsafe { sys::Sleep(2000) };
    }
}

/// One-shot diagnostic: dump the app's console-driver state structures when
/// the input pipeline has died (events pending, no reads for seconds).
fn dump_console_freeze_state(pending: u32) {
    static DUMPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if DUMPED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let ctx = crate::shim::CONSOLE_WAIT_CTX.load(std::sync::atomic::Ordering::Relaxed);
    vlog!("freeze-dump: pending {pending} events, console wait ctx {ctx:#x}");
    if ctx == 0 {
        return;
    }
    dump_mem("ctx-region", ctx.saturating_sub(0x80), 0x200);
    let g = read_u64(ctx).unwrap_or(0);
    if g != 0 && (g as isize - ctx as isize).unsigned_abs() <= 0x4000 {
        dump_mem("G", g, 0x200);
        for (name, off) in [("A", 0usize), ("B", 8), ("C", 0x20), ("D", 0x28)] {
            if let Some(p) = read_u64(g + off) {
                if p > 0x10000 && p < 0x0000_8000_0000_0000 {
                    dump_mem(name, p, 0x140);
                }
            }
        }
    }
}

fn read_u64(addr: usize) -> Option<usize> {
    if !sys::is_readable(addr, 8) {
        return None;
    }
    Some(unsafe { *(addr as *const usize) })
}

fn dump_mem(label: &str, base: usize, len: usize) {
    let mut addr = base;
    while addr < base + len {
        if !sys::is_readable(addr, 16) {
            vlog!("freeze-dump: {label} {addr:#x}: <unreadable>");
            addr += 16;
            continue;
        }
        let v0 = unsafe { *(addr as *const u64) };
        let v1 = unsafe { *((addr + 8) as *const u64) };
        vlog!("freeze-dump: {label} {addr:#x}: {v0:016x} {v1:016x}");
        addr += 16;
    }
}

fn start_input_probe() {
    if !crate::diag::verbose() {
        return;
    }
    unsafe {
        sys::CreateThread(
            std::ptr::null_mut(),
            0,
            Some(input_probe_thread),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );
    }
}

/// The loader's own std panic machinery touches Rust TLS, which target
/// threads have re-pointed at the target's block; report panics with a raw
/// WriteFile so the real message is never lost to a double panic.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("peldr: RUST PANIC: {info}\n");
        crate::sys::raw_stderr(&msg);
    }));
}

/// Diagnostic fallback for crashes in target code: report the faulting
/// address and which mapped image (if any) it belongs to.
fn install_crash_filter() {
    unsafe {
        sys::SetUnhandledExceptionFilter(Some(crash_filter));
    }
}

unsafe extern "system" fn crash_filter(info: *mut sys::ExceptionPointers) -> i32 {
    unsafe {
        let er = (*info).exception_record;
        let code = (*er).exception_code;
        let addr = (*er).exception_address as usize;
        let rip = if !(*info).context_record.is_null() {
            let ctx = (*info).context_record as *const u8;
            *(ctx.add(0xF8) as *const usize) // CONTEXT.Rip (x64)
        } else {
            addr
        };
        let mut out = format!(
            "peldr: FATAL: unhandled exception {code:#010x} at {addr:#x} (rip {rip:#x})\n"
        );
        let view = crate::shim::view_if_installed();
        if let Some(v) = view {
            if let Ok(images) = v.images.lock() {
                for im in images.iter() {
                    if rip >= im.base && rip < im.base + im.size as usize {
                        out.push_str(&format!(
                            "peldr:   faulting in {} at +{:#x} (base {:#x})\n",
                            im.name,
                            rip - im.base,
                            im.base
                        ));
                    }
                }
            }
        }
        let params = (*er).number_parameters as usize;
        for i in 0..params.min(15) {
            out.push_str(&format!("peldr:   param[{i}] = {:#x}\n", (*er).exception_information[i]));
        }
        sys::raw_stderr(&out);
    }
    sys::terminate_self(127)
}

fn patch_peb(base: usize, size_of_image: u32, path: &Path, argv: &[String]) {
    let full = path.display().to_string();
    let file = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| full.clone());
    let cmd = build_command_line(argv);

    let full_w = leak_wide(&sys::to_wide(&full));
    let file_w = leak_wide(&sys::to_wide(&file));
    let (cmd_ptr, cmd_len) = crate::shim::set_command_line(&cmd);

    unsafe {
        let peb = sys::peb();
        if crate::diag::verbose() {
            let p = *((peb + PEB_PROCESS_PARAMS) as *const usize);
            let us = |at: usize| -> String {
                let len = *(at as *const u16) as usize;
                let buf = *((at + 8) as *const *const u16);
                if buf.is_null() || len == 0 || len > 4096 {
                    format!("(len {len})")
                } else {
                    String::from_utf16_lossy(std::slice::from_raw_parts(buf, len / 2))
                }
            };
            vlog!("peb: old ImagePathName = {}", us(p + PARAMS_IMAGE_PATH_NAME));
            vlog!("peb: old CommandLine   = {}", us(p + PARAMS_COMMAND_LINE));
        }
        // The target thinks it is the process image.
        *((peb + PEB_IMAGE_BASE) as *mut usize) = base;
        let params = *((peb + PEB_PROCESS_PARAMS) as *const usize);
        write_unicode_string(params + PARAMS_COMMAND_LINE, cmd_ptr, cmd_len);
        write_unicode_string(params + PARAMS_IMAGE_PATH_NAME, full_w.ptr, full_w.byte_len);
        if crate::diag::verbose() {
            vlog!("peb: new CommandLine   = {cmd:?}");
        }
        // Main module LDR entry names (GetModuleFileNameW(NULL) et al.).
        let ldr = *((peb + PEB_LDR) as *const usize);
        if ldr != 0 {
            let head = ldr + LDR_IN_LOAD_ORDER;
            let first = *(head as *const usize);
            if first != head && first != 0 {
                let _ = LDR_LINKS;
                write_unicode_string(first + LDR_FULL_DLL_NAME, full_w.ptr, full_w.byte_len);
                write_unicode_string(first + LDR_BASE_DLL_NAME, file_w.ptr, file_w.byte_len);
            }
        }
    }
    vlog!("peb patched: image base {base:#x}, size {size_of_image:#x}, argv0 {:?}", argv.first());
}

/// (buffer pointer, byte length without NUL)
struct Wide {
    ptr: *mut u16,
    byte_len: u16,
}

fn leak_wide(w: &[u16]) -> Wide {
    let byte_len = (w.len().saturating_sub(1) * 2) as u16;
    let b = w.to_vec().into_boxed_slice();
    Wide {
        ptr: Box::into_raw(b) as *mut u16,
        byte_len,
    }
}

unsafe fn write_unicode_string(at: usize, buf: *mut u16, byte_len: u16) {
    unsafe {
        *(at as *mut u16) = byte_len;
        *((at + 2) as *mut u16) = byte_len + 2;
        *((at + 8) as *mut usize) = buf as usize;
    }
}

/// CommandLineToArgvW-compatible quoting.
pub fn quote_arg(s: &str) -> String {
    if !s.is_empty() && !s.contains([' ', '\t', '"']) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in s.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('\\');
                out.push('"');
            }
            _ => {
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

fn build_command_line(argv: &[String]) -> String {
    let mut parts = Vec::with_capacity(argv.len());
    for a in argv {
        parts.push(quote_arg(a));
    }
    if parts.is_empty() {
        return String::new();
    }
    parts.join(" ")
}
