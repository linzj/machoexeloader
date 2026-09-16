//! Module TLS for manually mapped images.
//!
//! Windows target code reaches thread locals through `_tls_index` plus
//! TEB->ThreadLocalStoragePointer[index], and image code linked as a main
//! executable may even hardcode slot 0 (`mov rcx, fs:[58h]; mov rax, [rcx]`)
//! because a real process's exe is assigned TLS slot 0. The manually mapped
//! target is the process image from its own point of view, so it must get
//! slot 0 -- which ntdll gave to the loader itself.
//!
//! Layout of the per-thread arrays we build:
//!   [0]              target main image's TLS block (on target threads)
//!   [1 .. C)         the host's own blocks, untouched
//!   [C]              the loader's original block; the loader's _tls_index
//!                    inside its own image is rewritten to C so the loader's
//!                    Rust thread-locals keep working everywhere
//!   [C+1 .. C+k)     self-mapped DLL images' blocks
//! where C = number of host modules with a TLS directory (== ntdll's TLS
//! entry count; no module ever unloads). If a host DLL with TLS loads later,
//! ntdll claims slot C and reallocates thread arrays: maintain() then shifts
//! the loader and DLL slots up and rebuilds our arrays.
//!
//! Teardown: ntdll frees TLS arrays and per-module blocks from its private
//! LdrpTlsHeap, so at thread exit the TEB must not point at our process-heap
//! array -- one-shot threads get it nulled (ntdll's teardown then skips all
//! frees), pool threads get ntdll's own array back for reuse. One-shot
//! threads run their FLS record through ntdll's own RtlProcessFlsData before
//! the null: LdrShutdownThread executes FLS callbacks after it, and those
//! callbacks read thread-locals through the very pointer being nulled.

use std::alloc::{alloc, Layout};
use std::sync::{Mutex, OnceLock};

use crate::image::{Image, ImageKind};
use crate::sys;
use crate::vlog;

const MAIN_SLOT: usize = 0;

struct TlsImageInfo {
    is_main: bool,
    base: usize,
    index_addr: usize,
    slot: usize,
    block_size: usize,
    template_addr: usize,
    template_size: usize,
    callbacks_addr: Option<usize>,
}

struct ThreadRec {
    teb: usize,
    /// Thread id: TEB addresses are reused by the OS, so a matching TEB
    /// pointer alone does not mean the record is the current thread's.
    tid: u32,
    is_target: bool,
    /// Pool threads are reused after a callback returns: keep ntdll's own
    /// array for them. One-shot threads get it nulled on the way out.
    reusable: bool,
    /// One block per entry of `TlsState::images`, same order.
    blocks: Vec<usize>,
    /// The ntdll-owned array this thread had before we replaced it; restored
    /// on thread exit so ntdll's teardown frees only its own allocations.
    original: usize,
    /// The array we installed; if the TEB no longer points at it, ntdll
    /// reallocated behind our back and no restore is needed.
    ours: usize,
}

struct TlsState {
    /// Host TLS module count; also the loader's new slot.
    base_slot: usize,
    loader_index_addr: usize,
    images: Vec<TlsImageInfo>,
    threads: Vec<ThreadRec>,
}

/// Build the per-thread array: host entries [0..base), loader block at
/// [base), target block (optionally) at [0], DLL blocks at their slots.
fn build_array(
    images: &[TlsImageInfo],
    base_slot: usize,
    host: &[usize],
    blocks: &[usize],
    target_block: Option<usize>,
) -> Vec<usize> {
    let dlls = images.iter().filter(|i| !i.is_main).count();
    let mut arr = host.to_vec();
    let loader_block = if host.is_empty() { 0 } else { host[0] };
    arr.resize(base_slot + 1 + dlls, 0);
    arr[base_slot] = loader_block;
    if let Some(tb) = target_block {
        arr[MAIN_SLOT] = tb;
    }
    for (k, si) in images.iter().enumerate() {
        if !si.is_main {
            arr[si.slot] = blocks[k];
        }
    }
    arr
}

static STATE: Mutex<Option<TlsState>> = Mutex::new(None);

/// Locate the `_tls_index` DWORD inside the loader's own image (i.e. the
/// AddressOfIndex of its TLS directory).
fn loader_tls_index_addr() -> Option<usize> {
    let h = sys::module_from_address(loader_tls_index_addr as *const () as usize);
    let base = h as usize;
    if base == 0 {
        return None;
    }
    unsafe {
        if *(base as *const u16) != 0x5A4D {
            return None;
        }
        let e = *((base + 0x3C) as *const u32) as usize;
        if e >= 0x1000 || *((base + e) as *const u32) != 0x0000_4550 {
            return None;
        }
        let opt = base + e + 24;
        if *(opt as *const u16) != 0x020B {
            return None;
        }
        let ndir = *((opt + 108) as *const u32);
        if ndir <= 9 {
            return None;
        }
        let tls_rva = *((opt + 112 + 9 * 8) as *const u32) as usize;
        if tls_rva == 0 {
            return None;
        }
        let index_va = *((base + tls_rva + 16) as *const usize);
        if index_va == 0 {
            None
        } else {
            Some(index_va)
        }
    }
}

pub fn initialize(images: &[Image]) -> Result<(), String> {
    let mut infos = Vec::new();
    for img in images {
        if img.kind == ImageKind::Bridged {
            continue;
        }
        let Some(t) = img.tls.clone() else { continue };
        let block_size = t.template_size as usize + t.zero_fill as usize;
        if block_size == 0 && t.callbacks_rva.is_none() {
            continue;
        }
        infos.push((img, t, block_size));
    }
    if infos.is_empty() {
        return Ok(());
    }
    let base = count_host_tls_modules();
    let loader_index_addr = loader_tls_index_addr().unwrap_or(0);
    let mut next_dll_slot = base + 1;
    vlog!(
        "tls: {} mapped image(s) with TLS, host TLS modules {base}, loader slot {base}",
        infos.len()
    );
    if loader_index_addr == 0 {
        vlog!("tls: WARNING loader TLS directory not found; loader thread-locals may break on target threads");
    }

    let mut sis = Vec::new();
    for (img, t, block_size) in &infos {
        let is_main = img.kind == ImageKind::MainExe;
        let slot = if is_main {
            MAIN_SLOT
        } else {
            let s = next_dll_slot;
            next_dll_slot += 1;
            s
        };
        let index_addr = if t.index_rva != 0 { img.addr_of(t.index_rva) } else { 0 };
        if index_addr != 0 {
            // Images are still read/write here (reprotect runs later).
            unsafe {
                *(index_addr as *mut u32) = slot as u32;
            }
        }
        vlog!("tls: {} -> slot {slot} (block {block_size:#x} bytes)", img.name);
        sis.push(TlsImageInfo {
            is_main,
            base: img.base,
            index_addr,
            slot,
            block_size: *block_size,
            template_addr: if t.template_size > 0 { img.addr_of(t.template_rva) } else { 0 },
            template_size: t.template_size as usize,
            callbacks_addr: t.callbacks_rva.map(|r| img.addr_of(r)),
        });
    }

    if loader_index_addr != 0 {
        // Move the loader's own TLS index into the free slot beyond the
        // host's: the target needs slot 0.
        write_index(loader_index_addr, base)?;
    }

    *STATE.lock().unwrap() = Some(TlsState {
        base_slot: base,
        loader_index_addr,
        images: sis,
        threads: Vec::new(),
    });
    // The loader's main thread keeps running our code (join/exit paths), so
    // its Rust TLS must keep working: attach it, preserving slot 0.
    attach_for_teb(sys::teb(), false, true)?;
    Ok(())
}

/// Attach the current thread for running target code: slot 0 becomes the
/// target's block. The thread is expected to die right after (one-shot).
pub fn attach_current_thread() -> Result<(), String> {
    attach_for_teb(sys::teb(), true, false)
}

/// Same, for thread-pool threads that keep running other work afterwards.
pub fn attach_reusable_thread() -> Result<(), String> {
    attach_for_teb(sys::teb(), true, true)
}

/// Loader-side helper thread (not running target code): extend its array so
/// the loader's own Rust TLS (index moved to slot C) keeps working there.
pub fn extend_current_loader_thread() -> Result<(), String> {
    attach_for_teb(sys::teb(), false, true)
}

fn attach_for_teb(teb: usize, is_target: bool, reusable: bool) -> Result<(), String> {
    let mut guard = STATE.lock().unwrap();
    let Some(st) = guard.as_mut() else { return Ok(()) };
    maintain_locked(st)?;
    let tid = unsafe { sys::GetCurrentThreadId() };
    if let Some(pos) = st.threads.iter().position(|t| t.teb == teb) {
        if st.threads[pos].tid == tid {
            vlog!("tls: thread {teb:#x} (tid {tid}) already attached; reusing array");
            return Ok(());
        }
        // TEB address reused by a new thread: drop the stale record.
        st.threads.remove(pos);
    }
    let cur = sys::tls_array_for(teb);
    let host: Vec<usize> = if cur.is_null() {
        vec![0; st.base_slot]
    } else {
        (0..st.base_slot).map(|i| unsafe { *cur.add(i) }).collect()
    };
    let mut blocks = Vec::with_capacity(st.images.len());
    for si in &st.images {
        blocks.push(alloc_block(si)?);
    }
    let target_block = if is_target {
        let k = st.images.iter().position(|i| i.is_main);
        k.map(|k| blocks[k])
    } else {
        None
    };
    let arr = build_array(&st.images, st.base_slot, &host, &blocks, target_block);
    let len = arr.len();
    let ours = leak_arr(arr) as usize;
    sys::set_tls_array_for(teb, ours as *mut usize);
    st.threads.push(ThreadRec {
        teb,
        tid,
        is_target,
        reusable,
        blocks,
        original: cur as usize,
        ours,
    });
    vlog!("tls: thread {teb:#x} (tid {tid}) attached (target {is_target}, array {len} entries)");
    Ok(())
}

/// Undo the per-thread array surgery before the thread exits: ntdll's thread
/// teardown frees the per-module blocks and the array itself using its own
/// bookkeeping, so the TEB must point back at the array ntdll created.
pub fn restore_current_thread_array() {
    let teb = sys::teb();
    let tid = unsafe { sys::GetCurrentThreadId() };
    let (original, ours, reusable) = {
        let mut guard = match STATE.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let Some(st) = guard.as_mut() else {
            vlog!("tls: restore on thread {teb:#x} (tid {tid}) — TLS state absent");
            return;
        };
        let Some(pos) = st
            .threads
            .iter()
            .position(|t| t.teb == teb && t.tid == tid)
        else {
            vlog!("tls: restore on untracked thread {teb:#x} (tid {tid}) — no-op");
            return;
        };
        let (original, ours, reusable) = {
            let rec = &st.threads[pos];
            (rec.original, rec.ours, rec.reusable)
        };
        st.threads.remove(pos);
        (original, ours, reusable)
    };
    // The lock is dropped before the branches below: the FLS step runs
    // target callbacks, which may call back into the loader (LoadLibrary ->
    // on_host_module_load -> STATE).
    if sys::tls_array_for(teb) as usize == ours {
        if reusable {
            // Pool thread: it will run more work; give ntdll its array back.
            sys::set_tls_array_for(teb, original as *mut usize);
            vlog!("tls: thread {teb:#x} (tid {tid}) array restored for reuse");
        } else {
            // One-shot thread about to die: process its FLS record while the
            // array is still installed, then null the pointer so ntdll's
            // thread teardown (LdrpFreeTls) skips all frees -- its private
            // LdrpTlsHeap may only ever free ntdll's own allocations.
            process_fls_for_exit(teb);
            sys::set_tls_array_for(teb, std::ptr::null_mut());
            vlog!("tls: thread {teb:#x} (tid {tid}) array nulled for exit");
        }
    } else {
        // ntdll reallocated (a TLS module loaded); the TEB already points at
        // ntdll's fresh array, keep it.
        vlog!(
            "tls: thread {teb:#x} (tid {tid}) restore skipped: TEB array {:#x} != ours {ours:#x}",
            sys::tls_array_for(teb) as usize
        );
    }
}

/// ntdll!RtlProcessFlsData (exported). LdrShutdownThread calls it with
/// (teb->FlsData, 1) to run a thread's FLS callbacks and unlink the record.
fn rtl_process_fls_data() -> Option<unsafe extern "system" fn(usize, u32)> {
    static F: OnceLock<Option<usize>> = OnceLock::new();
    let p = *F.get_or_init(|| {
        sys::load_library_a("ntdll.dll")
            .ok()
            .and_then(|h| sys::get_proc(h, "RtlProcessFlsData"))
    });
    p.map(|p| unsafe { std::mem::transmute(p) })
}

/// Run the exiting thread's FLS record through ntdll's own processing while
/// the TLS array is still valid, then clear TEB->FlsData so ntdll's later
/// LdrShutdownThread pass finds nothing (the record is already unlinked; a
/// second call would trip its list integrity check). Without this, FLS
/// callbacks registered by target code run after the array was nulled and
/// fault reading thread-locals through the NULL pointer.
fn process_fls_for_exit(teb: usize) {
    let fls = sys::fls_data_for(teb);
    if fls == 0 {
        return;
    }
    static OFF: OnceLock<bool> = OnceLock::new();
    if *OFF.get_or_init(|| std::env::var_os("PELDR_NO_FLS_EXIT").is_some()) {
        return;
    }
    match rtl_process_fls_data() {
        Some(f) => {
            unsafe { f(fls, 1) };
            sys::set_fls_data_for(teb, 0);
            vlog!("tls: thread {teb:#x} FLS record {fls:#x} processed before exit");
        }
        None => {
            vlog!("tls: thread {teb:#x} has FLS record {fls:#x} but RtlProcessFlsData is unavailable");
        }
    }
}

/// Called from the LoadLibrary shims after a host module was loaded: ntdll
/// may have just claimed slot C for a new TLS module.
pub fn on_host_module_load() {
    crate::diag::bump(&crate::diag::HOST_LOADS);
    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if let Some(st) = guard.as_mut() {
        if let Err(e) = maintain_locked(st) {
            crate::rerr!("TLS maintenance failed: {e}");
        }
    }
}

/// (tid, is_target, reusable) of every tracked thread, for the watchdog.
pub fn snapshot_threads() -> Vec<(u32, bool, bool)> {
    let guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    let Some(st) = guard.as_ref() else { return Vec::new() };
    st.threads
        .iter()
        .map(|t| (t.tid, t.is_target, t.reusable))
        .collect()
}

fn maintain_locked(st: &mut TlsState) -> Result<(), String> {
    let c = count_host_tls_modules();
    if c > st.base_slot {
        migrate(st, c)?;
    }
    Ok(())
}

fn migrate(st: &mut TlsState, new_count: usize) -> Result<(), String> {
    let delta = new_count - st.base_slot;
    vlog!(
        "tls: host loaded {delta} TLS-bearing module(s); moving our slots up (base {} -> {new_count})",
        st.base_slot
    );
    for si in &mut st.images {
        if si.is_main {
            continue;
        }
        si.slot += delta;
        if si.index_addr != 0 {
            write_index(si.index_addr, si.slot)?;
        }
    }
    if st.loader_index_addr != 0 {
        write_index(st.loader_index_addr, new_count)?;
    }
    let TlsState {
        base_slot,
        images,
        threads,
        ..
    } = st;
    *base_slot = new_count;
    threads.retain(|rec| unsafe { *((rec.teb + 0x48) as *const u32) == rec.tid });
    for rec in threads.iter_mut() {
        let cur = sys::tls_array_for(rec.teb);
        // ntdll reallocated each thread's array when the module loaded; the
        // fresh array becomes the one to hand back at thread exit.
        rec.original = cur as usize;
        let host: Vec<usize> = (0..new_count).map(|i| unsafe { *cur.add(i) }).collect();
        let target_block = if rec.is_target {
            images
                .iter()
                .position(|i| i.is_main)
                .map(|k| rec.blocks[k])
        } else {
            None
        };
        let arr = build_array(images, new_count, &host, &rec.blocks, target_block);
        let ours = leak_arr(arr) as usize;
        rec.ours = ours;
        sys::set_tls_array_for(rec.teb, ours as *mut usize);
    }
    Ok(())
}

/// Whether this tid is one of the threads we bootstrapped (has a target
/// TLS array). Diagnostic helper.
pub fn is_thread_tracked(tid: u32) -> bool {
    let guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let Some(st) = guard.as_ref() else { return false };
    st.threads.iter().any(|r| r.tid == tid)
}

/// Register TLS for an image mapped after the target started (a runtime
/// LoadLibrary self-map). It takes the next free DLL slot; the module's index
/// is written, every tracked thread gets a fresh block (template copy) and a
/// rebuilt array, so the module's thread-locals work on all threads. Its TLS
/// callbacks then run with DLL_PROCESS_ATTACH (lpReserved=0: dynamic load).
pub fn register_runtime_image(img: &Image) -> Result<(), String> {
    let Some(t) = img.tls.as_ref() else { return Ok(()) };
    if t.index_rva == 0 && t.template_size == 0 && t.callbacks_rva.is_none() {
        return Ok(());
    }
    let mut guard = STATE.lock().unwrap();
    let Some(st) = guard.as_mut() else { return Ok(()) };
    maintain_locked(st)?;
    let slot = st.base_slot + 1 + st.images.iter().filter(|i| !i.is_main).count();
    let block_size = t.template_size as usize + t.zero_fill as usize;
    let index_addr = if t.index_rva != 0 { img.addr_of(t.index_rva) } else { 0 };
    if index_addr != 0 {
        write_index(index_addr, slot)?;
    }
    let si = TlsImageInfo {
        is_main: false,
        base: img.base,
        index_addr,
        slot,
        block_size,
        template_addr: if t.template_size > 0 { img.addr_of(t.template_rva) } else { 0 },
        template_size: t.template_size as usize,
        callbacks_addr: t.callbacks_rva.map(|r| img.addr_of(r)),
    };
    vlog!(
        "tls: runtime image {} -> slot {slot} (block {block_size:#x} bytes)",
        img.name
    );
    let TlsState {
        base_slot,
        images,
        threads,
        ..
    } = st;
    images.push(si);
    let si = images.last().unwrap();
    for rec in threads.iter_mut() {
        let b = alloc_block(si)?;
        rec.blocks.push(b);
        let cur = sys::tls_array_for(rec.teb);
        let mut host: Vec<usize> = (0..*base_slot).map(|i| unsafe { *cur.add(i) }).collect();
        // Our arrays keep the loader's block at [base]; build_array takes the
        // loader block from host[0], so carry it over explicitly.
        if !host.is_empty() {
            host[0] = unsafe { *cur.add(*base_slot) };
        }
        let target_block = if rec.is_target {
            images
                .iter()
                .position(|i| i.is_main)
                .map(|k| rec.blocks[k])
        } else {
            None
        };
        let arr = build_array(images, *base_slot, &host, &rec.blocks, target_block);
        let ours = leak_arr(arr) as usize;
        rec.ours = ours;
        sys::set_tls_array_for(rec.teb, ours as *mut usize);
    }
    // Module TLS callbacks, DLL_PROCESS_ATTACH with lpReserved=0 (dynamic load).
    if let Some(a) = si.callbacks_addr {
        let mut i = 0usize;
        loop {
            let f = unsafe { *((a + i * 8) as *const usize) };
            if f == 0 || i > 128 {
                break;
            }
            vlog!("tls: running runtime callback {f:#x} for image at {:#x}", img.base);
            let cb: unsafe extern "system" fn(usize, u32, usize) = unsafe { std::mem::transmute(f) };
            unsafe { cb(img.base, 1, 0) };
            i += 1;
        }
    }
    Ok(())
}

fn write_index(addr: usize, slot: usize) -> Result<(), String> {
    // May run after the image was reprotected read-only.
    let page = addr & !(sys::page_size() - 1);
    let old = sys::protect_get(page, sys::page_size(), sys::PAGE_READWRITE)?;
    unsafe {
        *(addr as *mut u32) = slot as u32;
    }
    sys::protect(page, sys::page_size(), old)?;
    Ok(())
}

fn alloc_block(si: &TlsImageInfo) -> Result<usize, String> {
    let size = si.block_size.max(1);
    let layout = Layout::from_size_align(size, 16).map_err(|e| e.to_string())?;
    let p = unsafe { alloc(layout) };
    if p.is_null() {
        return Err(format!("TLS block allocation ({size} bytes) failed"));
    }
    unsafe {
        std::ptr::write_bytes(p, 0, size);
        if si.template_size > 0 {
            std::ptr::copy_nonoverlapping(si.template_addr as *const u8, p, si.template_size);
        }
    }
    Ok(p as usize)
}

fn leak_arr(arr: Vec<usize>) -> *mut usize {
    // One leading slot stays 0: ntdll's LdrpHandleTlsData may "upgrade" a
    // thread's TLS vector when a TLS-bearing host DLL loads, and frees the
    // previous vector via RtlFreeHeap(LdrpTlsHeap, *(TlsArray - 8)). For our
    // array that read lands on this guard slot, so the free becomes a
    // harmless free(NULL) instead of a heap fail-fast.
    let mut v = Vec::with_capacity(arr.len() + 1);
    v.push(0usize);
    v.extend_from_slice(&arr);
    let raw = Box::into_raw(v.into_boxed_slice()) as *mut usize;
    unsafe { raw.add(1) }
}

/// Run the TLS callbacks of all self-mapped images with DLL_THREAD_ATTACH.
/// A real process runs these for every thread (ntdll does it from its own
/// loader database); self-mapped images are invisible to ntdll, so our
/// thread bootstraps must do it. Collected under the lock, run outside it --
/// callbacks may call back into LoadLibrary and the TLS machinery.
pub fn run_thread_attach_callbacks() {
    let cbs: Vec<(usize, usize)> = {
        let guard = match STATE.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let Some(st) = guard.as_ref() else { return };
        let mut v = Vec::new();
        for si in &st.images {
            let Some(a) = si.callbacks_addr else { continue };
            let mut i = 0usize;
            loop {
                let f = unsafe { *((a + i * 8) as *const usize) };
                if f == 0 || i > 128 {
                    break;
                }
                v.push((f, si.base));
                i += 1;
            }
        }
        v
    };
    for (f, base) in cbs {
        let cb: unsafe extern "system" fn(usize, u32, usize) = unsafe { std::mem::transmute(f) };
        unsafe { cb(base, 2, 0) }; // DLL_THREAD_ATTACH
    }
}

/// Run the TLS callbacks of ALL images with DLL_PROCESS_ATTACH. lpReserved != 0
/// mirrors the "loaded at process start" semantics the target would see.
pub fn run_callbacks() {
    let cbs: Vec<(usize, usize)> = {
        let guard = STATE.lock().unwrap();
        let Some(st) = guard.as_ref() else { return };
        let mut v = Vec::new();
        for si in &st.images {
            let Some(a) = si.callbacks_addr else { continue };
            let mut i = 0usize;
            loop {
                let f = unsafe { *((a + i * 8) as *const usize) };
                if f == 0 || i > 128 {
                    break;
                }
                v.push((f, si.base));
                i += 1;
            }
        }
        v
    };
    for (f, base) in cbs {
        vlog!("tls: running callback {f:#x} for image at {base:#x}");
        let cb: unsafe extern "system" fn(usize, u32, usize) = unsafe { std::mem::transmute(f) };
        unsafe { cb(base, 1, 1) };
    }
}

/// Number of loaded host modules that carry a TLS data directory. Equal to
/// ntdll's internal TLS entry count in a process that never unloads modules.
pub fn count_host_tls_modules() -> usize {
    unsafe {
        let peb = sys::peb();
        let ldr = *((peb + 0x18) as *const usize);
        if ldr == 0 {
            return 0;
        }
        let head = ldr + 0x10;
        let mut cur = *(head as *const usize);
        let mut n = 0usize;
        let mut iters = 0usize;
        while cur != head && cur != 0 && iters < 4096 {
            iters += 1;
            let base = *((cur + 0x30) as *const usize);
            if base != 0 && module_has_tls(base) {
                n += 1;
            }
            cur = *(cur as *const usize);
        }
        n
    }
}

fn module_has_tls(base: usize) -> bool {
    unsafe {
        if *(base as *const u16) != 0x5A4D {
            return false;
        }
        let e = *((base + 0x3C) as *const u32) as usize;
        if e >= 0x1000 {
            return false;
        }
        if *((base + e) as *const u32) != 0x0000_4550 {
            return false;
        }
        let opt = base + e + 24;
        if *(opt as *const u16) != 0x020B {
            return false;
        }
        let ndir = *((opt + 108) as *const u32);
        if ndir <= 9 {
            return false;
        }
        *((opt + 112 + 9 * 8) as *const u32) != 0
    }
}
