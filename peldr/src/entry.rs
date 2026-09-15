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

    // Diagnostic: shift the phase between the app's startup timers and the
    // console's input-batch delivery.
    if let Some(ms) = std::env::var_os("PELDR_ENTRY_DELAY_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u32>() {
            vlog!("entry delay: sleeping {ms} ms before creating the target thread");
            unsafe { sys::Sleep(ms) };
        }
    }

    // Diagnostic: run the target entry on the loader's PRIMARY thread via a
    // fiber (18MB fiber stack), so the app's "main" thread identity matches
    // a real process.
    if std::env::var_os("PELDR_PRIMARY_FIBER").is_some() {
        vlog!("primary-fiber mode: running entry on the primary thread");
        let param = Box::into_raw(Box::new(EntryStart { entry })) as *mut c_void;
        let fiber = unsafe { sys::CreateFiber(stack, Some(fiber_start), param) };
        vlog!("primary-fiber: CreateFiber -> {fiber:p} (gle {})", unsafe { sys::GetLastError() });
        if fiber.is_null() {
            eprintln!("peldr: failed to create fiber ({})", unsafe { sys::GetLastError() });
            std::process::exit(127);
        }
        let converted = unsafe { sys::ConvertThreadToFiber(std::ptr::null_mut()) };
        vlog!("primary-fiber: ConvertThreadToFiber -> {converted:p} (gle {})", unsafe { sys::GetLastError() });
        if converted.is_null() {
            eprintln!("peldr: ConvertThreadToFiber failed ({})", unsafe { sys::GetLastError() });
            std::process::exit(127);
        }
        vlog!("primary-fiber: switching");
        unsafe { sys::SwitchToFiber(fiber) };
        vlog!("primary-fiber: returned from fiber");
        // Returned from the fiber without exiting the process.
        std::process::exit(127);
    }

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

unsafe extern "system" fn fiber_start(p: *mut c_void) -> ! {
    crate::rerr!("primary-fiber: fiber_start entered");
    if let Some(ms) = std::env::var_os("PELDR_FIBER_PAUSE_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u32>() {
            crate::rerr!("primary-fiber: pausing {ms} ms before callbacks (attach now)");
            unsafe { sys::Sleep(ms) };
        }
    }
    let es = unsafe { Box::from_raw(p as *mut EntryStart) };
    // The primary thread was pre-attached by tls::initialize() as a loader
    // thread (is_target=false, array[0] = host block). Peel that record off
    // so attach_current_thread does a full target-layout attach.
    crate::tls::restore_current_thread_array();
    if let Err(e) = crate::tls::attach_current_thread() {
        crate::rerr!("TLS setup failed on primary-fiber thread: {e}");
        sys::terminate_self(127);
    }
    crate::rerr!("primary-fiber: tls attached");
    crate::tls::run_callbacks();
    crate::tls::run_thread_attach_callbacks();
    vlog!("jumping to target entry {:#x} (primary fiber)", es.entry);
    let f: unsafe extern "system" fn() -> i32 = unsafe { std::mem::transmute(es.entry) };
    let ret = unsafe { f() };
    crate::tls::restore_current_thread_array();
    vlog!("target entry returned {ret} (primary fiber)");
    sys::terminate_self(ret as u32)
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
        let ctx0 = crate::shim::CONSOLE_WAIT_CTX.load(std::sync::atomic::Ordering::Relaxed);
        let tty = if ctx0 != 0 { read_u64(ctx0).unwrap_or(0) } else { 0 };
        if tty != 0 {
            // G+0x58 flags, G+0x118 state, G+0x130 wait handle,
            // G+0x120/0x128: dispatch selector (0 => raw path) + buffer ptr
            let flags = read_u64(tty + 0x58).map(|v| v as u32).unwrap_or(0);
            let state = read_u64(tty + 0x118).map(|v| v as u32).unwrap_or(0);
            let wh = read_u64(tty + 0x130).unwrap_or(0);
            let sel = read_u64(tty + 0x120).map(|v| v as u32).unwrap_or(0);
            let buf = read_u64(tty + 0x128).unwrap_or(0);
            vlog!(
                "console state: flags={flags:#010x} state={state:#x} wait={wh:#x} sel={sel:#x} buf={buf:#x}"
            );
        }
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
        unsafe { sys::Sleep(if tick < 150 { 100 } else { 2000 }) };
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
            // Hand-built LDR entries break ntdll's private module index
            // (RB tree/hash) -- diagnostic only, off by default.
            if std::env::var_os("PELDR_LDR_ENTRY").is_some() {
                install_ldr_entry(peb, base, size_of_image, &full_w, &file_w);
            }
        }
    }
    vlog!("peb patched: image base {base:#x}, size {size_of_image:#x}, argv0 {:?}", argv.first());
}

/// Insert a real LDR_DATA_TABLE_ENTRY for the mapped image into the three
/// PEB module lists, so module enumeration by name/address finds the target
/// image itself (like a normally loaded main module).
unsafe fn install_ldr_entry(
    peb: usize,
    base: usize,
    size_of_image: u32,
    full_w: &Wide,
    file_w: &Wide,
) {
    #[repr(C)]
    struct ListEntry {
        flink: usize,
        blink: usize,
    }
    #[repr(C)]
    struct LdrEntry {
        in_load_order: ListEntry,       // +0x00
        in_memory_order: ListEntry,     // +0x10
        in_init_order: ListEntry,       // +0x20
        dll_base: usize,                // +0x30
        entry_point: usize,             // +0x38
        size_of_image: u32,             // +0x40
        _pad: u32,
        full_dll_name: [u8; 16],        // +0x48 (UNICODE_STRING)
        base_dll_name: [u8; 16],        // +0x58
        flags: u32,                     // +0x68
        pad2: u32,
    }
    unsafe {
        let ldr = *((peb + PEB_LDR) as *const usize);
        if ldr == 0 {
            return;
        }
        // The loader's own first entry keeps the batch: we link the mapped
        // image in directly after it in all three lists.
        let load_head = ldr + LDR_IN_LOAD_ORDER; // InLoadOrderModuleList head
        // Offsets of the list heads inside PEB_LDR_DATA: InLoadOrder +0x10,
        // InMemoryOrder +0x20, InInitializationOrder +0x30.
        let mem_head = ldr + 0x20;
        let init_head = ldr + 0x30;

        let e = match core::alloc::Layout::from_size_align(std::mem::size_of::<LdrEntry>(), 16) {
            Ok(l) => unsafe { std::alloc::alloc(l) as *mut LdrEntry },
            Err(_) => std::ptr::null_mut(),
        };
        if e.is_null() {
            return;
        }
        std::ptr::write_bytes(e as *mut u8, 0, std::mem::size_of::<LdrEntry>());
        (*e).dll_base = base;
        (*e).size_of_image = size_of_image;
        let first = *(load_head as *const usize);
        (*e).flags = if first != load_head && first != 0 {
            *((first + 0x68) as *const u32)
        } else {
            0
        };
        // Names (UNICODE_STRING inside the entry).
        write_unicode_string(e as usize + 0x48, full_w.ptr, full_w.byte_len);
        write_unicode_string(e as usize + 0x58, file_w.ptr, file_w.byte_len);

        // Link into each list, right after the head (so the mapped image is
        // the FIRST module the target sees).
        let link = |entry_off: usize, head: usize| {
            let e_link = e as usize + entry_off;
            let old_first = *(head as *const usize);
            *((e_link) as *mut usize) = old_first; // Flink = old first
            *((e_link + 8) as *mut usize) = head; // Blink = head
            *(head as *mut usize) = e_link; // head.Flink = us
            *((old_first + 8) as *mut usize) = e_link; // old first's Blink = us
        };
        link(0x00, load_head);
        link(0x10, mem_head);
        link(0x20, init_head);
        vlog!("peb: installed LDR entry {:#x} for the mapped image", e as usize);
    }
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
