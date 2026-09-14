//! Thread-local variables (TLV) support.
//!
//! macOS arm64 TLV access compiles to `ldr x8,[desc]; blr x8`, where `desc` is
//! a 24-byte descriptor in __DATA,__thread_vars. The linker leaves desc[0] as
//! a chained fixup bound to `__tlv_bootstrap` and desc[+16] as the variable's
//! offset inside the thread block. dyld rewrites each descriptor at load time:
//!
//! ```text
//! +0  u64  thunk   -> _tlv_get_addr            (we bind it to `tlv_thunk`)
//! +8  u32  key                                 (pthread key, one per section)
//! +12 u32  offset                              (variable offset in the block)
//! +16 i32  initial-content offset from &desc[16] (points at __thread_data)
//! +20 u32  total block size (__thread_data + __thread_bss)
//! ```
//!
//! Our thunk stores the per-thread block with `pthread_setspecific(key, ...)`
//! (same as dyld's `instantiateVariable`), allocates it lazily with the initial
//! bytes copied from the image, and returns `block + offset`.

use std::alloc::{Layout, alloc_zeroed};
use std::ffi::c_void;

use crate::image::Image;
use crate::loader::Registry;
use crate::sys;
use crate::vlog;

const DESC_SIZE: usize = 24;

#[repr(C)]
pub struct TlvDescriptor {
    pub thunk: usize,
    pub key: u32,
    pub offset: u32,
    pub init_rel: i32,
    pub total_size: u32,
}

/// Installed into `desc->thunk`; target code calls it as `thunk(desc)`.
///
/// TLV thunks follow a special ABI on macOS: only x0/x16/x17 may be clobbered,
/// everything else (including x8 and q0-q7) must survive, so the compiler can
/// keep values live in registers across the call. Wrap the Rust body in a
/// naked save/restore trampoline, mirroring `_tlv_get_addr`.
#[unsafe(naked)]
pub extern "C" fn tlv_thunk(_desc: *mut TlvDescriptor) -> *mut c_void {
    core::arch::naked_asm!(
        "sub  sp, sp, #0x120",
        "stp  x1, x2, [sp, #0x00]",
        "stp  x3, x4, [sp, #0x10]",
        "stp  x5, x6, [sp, #0x20]",
        "stp  x7, x8, [sp, #0x30]",
        "stp  x9, x10, [sp, #0x40]",
        "stp  x11, x12, [sp, #0x50]",
        "stp  x13, x14, [sp, #0x60]",
        "stp  x15, x18, [sp, #0x70]",
        "stp  q0, q1, [sp, #0x80]",
        "stp  q2, q3, [sp, #0x90]",
        "stp  q4, q5, [sp, #0xa0]",
        "stp  q6, q7, [sp, #0xb0]",
        "stp  x29, x30, [sp, #0x100]",
        "bl   {inner}",
        "ldp  x29, x30, [sp, #0x100]",
        "ldp  q6, q7, [sp, #0xb0]",
        "ldp  q4, q5, [sp, #0xa0]",
        "ldp  q2, q3, [sp, #0x90]",
        "ldp  q0, q1, [sp, #0x80]",
        "ldp  x15, x18, [sp, #0x70]",
        "ldp  x13, x14, [sp, #0x60]",
        "ldp  x11, x12, [sp, #0x50]",
        "ldp  x9, x10, [sp, #0x40]",
        "ldp  x7, x8, [sp, #0x30]",
        "ldp  x5, x6, [sp, #0x20]",
        "ldp  x3, x4, [sp, #0x10]",
        "ldp  x1, x2, [sp, #0x00]",
        "add  sp, sp, #0x120",
        "ret",
        inner = sym tlv_thunk_inner,
    )
}

extern "C" fn tlv_thunk_inner(desc: *mut TlvDescriptor) -> *mut c_void {
    unsafe {
        let d = &*desc;
        let mut block = sys::tsd_get(d.key as u64);
        if block.is_null() {
            let total = (d.total_size as usize).max(1);
            let layout = Layout::from_size_align(total, 16).expect("bad TLV layout");
            block = alloc_zeroed(layout) as *mut c_void;
            if block.is_null() {
                eprintln!("mldr: TLS block allocation failed");
                std::process::exit(127);
            }
            let src = (desc as *const u8).add(16).offset(d.init_rel as isize);
            std::ptr::copy_nonoverlapping(src, block as *mut u8, total);
            vlog!(
                "tlv_thunk: block {block:p} for key {} (total {total})",
                d.key
            );
            sys::tsd_set(d.key as u64, block);
        }
        (block as *mut u8).add(d.offset as usize) as *mut c_void
    }
}

/// Fills in the runtime descriptor fields after fixups have bound desc[0].
pub fn initialize(reg: &Registry) -> Result<(), String> {
    for img in &reg.images {
        if img.macho.is_some() {
            init_image(img)?;
        }
    }
    Ok(())
}

fn init_image(img: &Image) -> Result<(), String> {
    let m = img.macho();
    let mut data: Option<(usize, u64)> = None;
    let mut bss_size = 0u64;
    let mut vars_sections: Vec<(u64, u64)> = Vec::new();
    for s in &m.segments {
        for sec in &s.sections {
            match sec.name.as_str() {
                "__thread_data" if sec.size > 0 => {
                    data = Some((img.addr_of(sec.addr), sec.size))
                }
                "__thread_bss" => bss_size += sec.size,
                "__thread_vars" if sec.size > 0 => vars_sections.push((sec.addr, sec.size)),
                _ => {}
            }
        }
    }
    for (addr, size) in vars_sections {
        let total = (data.map(|(_, sz)| sz).unwrap_or(0) + bss_size) as u32;
        let key = sys::pthread_key_new()?;
        let n = (size / DESC_SIZE as u64) as usize;
        vlog!(
            "{}: {n} TLV descriptor(s): pthread key {key}, block {total} bytes",
            img.install_name
        );
        for k in 0..n {
            let desc = img.addr_of(addr) + k * DESC_SIZE;
            unsafe {
                let var_off = *((desc + 16) as *const u32);
                let init_rel = match data {
                    Some((da, _)) => da as i64 - (desc + 16) as i64,
                    None => 0,
                };
                *((desc + 8) as *mut u32) = key as u32;
                *((desc + 12) as *mut u32) = var_off;
                *((desc + 16) as *mut i32) = init_rel as i32;
                *((desc + 20) as *mut u32) = total;
                if k < 4 {
                    vlog!(
                        "  TLV desc[{k}] @ {desc:#x}: key {} var_off {var_off:#x} init_rel {init_rel:#x} total {total}",
                        key as u32
                    );
                }
            }
        }
    }
    Ok(())
}
