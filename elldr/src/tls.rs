//! Target TLS support for the local-exec model.
//!
//! A non-PIE glibc executable's TLS accesses are baked as `%fs:`-relative
//! offsets computed by the linker, which assume the executable's TLS block
//! sits at `[TP - align_up(memsz, align), TP)`. In our process the main
//! program is elldr itself, so its own TLS block occupies that area of every
//! thread. We keep this crate's PT_TLS segment large enough (TLS_PAD) that
//! the loader's block always covers the target's region, and every thread
//! that runs target code fills the target block with the target's TLS
//! template in-place.

use std::sync::Mutex;

use crate::elf::PT_TLS;
use crate::image::{align_up, Image};
use crate::sys;
use crate::vlog;

/// Size of this crate's dummy TLS variable; bounds the largest target PT_TLS
/// block we can host below TP. Claude's block is 0x58b0 bytes.
pub const TLS_PAD_SIZE: usize = 0x10000;

thread_local! {
    /// Never read or written. Referenced once from prepare() so the linker
    /// keeps it; its only purpose is the PT_TLS size it contributes.
    static TLS_PAD: [u8; TLS_PAD_SIZE] = const { [0u8; TLS_PAD_SIZE] };
}

struct TlsState {
    template: usize,
    tdata_len: usize,
    memsz: usize,
    /// A_t = align_up(memsz, align): the target's assumed block size.
    block: usize,
}

static STATE: Mutex<Option<TlsState>> = Mutex::new(None);

/// Validate the pad invariant and record the target TLS layout.
pub fn prepare(img: &Image) -> Result<(), String> {
    // Materialize the pad so it cannot be optimized out of PT_TLS.
    let pad_at = TLS_PAD.with(|p| p.as_ptr() as usize);
    let Some(t) = img.tls() else {
        vlog!("tls: target has no PT_TLS");
        return Ok(());
    };
    let block = align_up(t.memsz, t.align.max(1)) as usize;
    let (own_memsz, own_align) =
        own_pt_tls().ok_or_else(|| "cannot read elldr's own PT_TLS".to_string())?;
    let own_block = align_up(own_memsz, own_align.max(1)) as usize;
    if own_block < block {
        return Err(format!(
            "elldr TLS pad too small: own block {own_block:#x} < target block {block:#x} \
             (raise TLS_PAD_SIZE)"
        ));
    }
    // Measured check: glibc must place our block at [TP - own_block, TP).
    let tp = sys::get_fs_base() as usize;
    let tls_data = own_tls_data()
        .ok_or_else(|| "dl_iterate_phdr reported no TLS data for elldr itself".to_string())?;
    if tls_data + block > tp {
        return Err(format!(
            "elldr TLS block [{tls_data:#x}, {tp:#x}) does not cover the target TLS region \
             TP-{block:#x}; glibc layout assumption broken"
        ));
    }
    vlog!(
        "tls: pad@{pad_at:#x} own_block={own_block:#x} target_block={block:#x} \
         (tdata={:#x} memsz={:#x}) TP-tls_data={:#x}",
        t.filesz,
        t.memsz,
        tp - tls_data
    );
    *STATE.lock().unwrap() = Some(TlsState {
        template: img.addr_of(t.vaddr),
        tdata_len: t.filesz as usize,
        memsz: t.memsz as usize,
        block,
    });
    Ok(())
}

/// Install the target TLS template into this thread's target block
/// (`[TP - block, TP)`), zeroing the tbss remainder. Must be called on
/// every thread before it executes target code — and only once per thread.
pub fn install_for_current_thread() {
    let guard = STATE.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return;
    };
    let tp = sys::get_fs_base() as usize;
    let base = tp - s.block;
    unsafe {
        std::ptr::copy_nonoverlapping(s.template as *const u8, base as *mut u8, s.tdata_len);
        if s.memsz > s.tdata_len {
            std::ptr::write_bytes((base + s.tdata_len) as *mut u8, 0, s.memsz - s.tdata_len);
        }
    }
    vlog!("tls: installed target block at {base:#x} (thread TP {tp:#x})");
}

/// This thread's target TLS block (dlpi_tls_data for the synthetic image).
pub fn target_block_base() -> Option<usize> {
    let guard = STATE.lock().unwrap();
    let s = guard.as_ref()?;
    Some(sys::get_fs_base() as usize - s.block)
}

/// (p_memsz, p_align) of the running elldr's own PT_TLS.
fn own_pt_tls() -> Option<(u64, u64)> {
    let phdr = sys::auxval(sys::AT_PHDR) as *const u8;
    let phnum = sys::auxval(sys::AT_PHNUM) as usize;
    if phdr.is_null() || phnum == 0 {
        return None;
    }
    for i in 0..phnum {
        let p = unsafe { phdr.add(i * 56) };
        let p_type = unsafe { *(p as *const u32) };
        if p_type == PT_TLS {
            let memsz = unsafe { *(p.add(40) as *const u64) };
            let align = unsafe { *(p.add(48) as *const u64) };
            return Some((memsz, align));
        }
    }
    None
}

/// Our own (main map) TLS block address for the current thread, measured via
/// dl_iterate_phdr's dlpi_tls_data.
fn own_tls_data() -> Option<usize> {
    let f = sys::dlsym_default("dl_iterate_phdr")?;
    let f: extern "C" fn(extern "C" fn(*mut u8, usize, *mut std::ffi::c_void) -> i32, *mut std::ffi::c_void) -> i32 =
        unsafe { std::mem::transmute(f) };
    extern "C" fn cb(info: *mut u8, _size: usize, data: *mut std::ffi::c_void) -> i32 {
        // struct dl_phdr_info: dlpi_tls_data sits at offset 56.
        let tls_data = unsafe { *(info.add(56) as *const usize) };
        if tls_data != 0 {
            unsafe { *(data as *mut usize) = tls_data };
            return 1;
        }
        0
    }
    let mut out: usize = 0;
    f(cb, &mut out as *mut usize as *mut std::ffi::c_void);
    if out == 0 { None } else { Some(out) }
}
