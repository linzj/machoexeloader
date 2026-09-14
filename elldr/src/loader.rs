//! Load orchestration: parse -> map -> bridge -> relocate -> TLS -> entry.

use crate::elf::ElfFile;
use crate::image::{Image, prot_str};
use crate::{imports, shim, sys, tls};
use crate::vlog;

pub fn run_program(target: &str, argv: Vec<String>, load_only: bool) -> Result<(), String> {
    let path = std::fs::canonicalize(target).map_err(|e| format!("{target}: {e}"))?;
    sys::init_logging();

    let elf = ElfFile::open(&path)?;
    if let Some(i) = &elf.interp {
        vlog!("interp: {i} (informational; elldr is the image loader)");
    }
    vlog!(
        "parsed {}: entry={:#x} phnum={} needed={:?}",
        path.display(),
        elf.entry,
        elf.phdrs.len(),
        elf.needed
    );
    let img = Image::map(elf)?;
    vlog!(
        "mapped {:#x}..{:#x} ({} load segments)",
        img.base,
        img.end,
        img.loads.len()
    );

    shim::init_reals()?;
    shim::set_target_path(&path)?;
    shim::set_target_image(&img);
    preload_host_libs();

    let stats = imports::bind_all(&img)?;
    vlog!(
        "relocs: jump_slot={} glob_dat={} abs64={} copy={} relative={} irelative={}",
        stats.jump_slot,
        stats.glob_dat,
        stats.abs64,
        stats.copy,
        stats.relative,
        stats.irelative.len()
    );
    if !stats.shim_hits.is_empty() {
        vlog!("shims: {}", stats.shim_hits.join(", "));
    }
    if !stats.weak_missing.is_empty() {
        vlog!("weak unresolved (-> 0): {}", stats.weak_missing.join(", "));
    }
    imports::run_irelative(&stats.irelative);
    tls::prepare(&img)?;
    shim::set_ctors(collect_ctors(&img));

    if load_only {
        print_images(&img, &stats);
        return Ok(());
    }
    crate::entry::run_target(&img, &argv)
}

/// Read the target's constructor/destructor tables from the mapped image.
fn collect_ctors(img: &Image) -> shim::Ctors {
    let e = &img.elf;
    let read = |va: u64, sz: u64| -> Vec<usize> {
        let mut v = Vec::new();
        if va == 0 || sz == 0 {
            return v;
        }
        for i in 0..sz / 8 {
            if let Some(b) = e.bytes(va + i * 8, 8) {
                v.push(u64::from_le_bytes(b.try_into().unwrap()) as usize);
            }
        }
        v
    };
    shim::Ctors {
        preinit: read(e.preinit_array, e.preinit_arraysz),
        init: e.init as usize,
        init_array: read(e.init_array, e.init_arraysz),
        fini: e.fini as usize,
        fini_array: read(e.fini_array, e.fini_arraysz),
    }
}

/// Preload host libraries the target will reach through bridged symbols so
/// late dlopens cannot surprise us (libgcc_s powers backtrace()/unwinding).
fn preload_host_libs() {
    for lib in ["libgcc_s.so.1", "libm.so.6"] {
        match sys::dlopen_path(lib, sys::RTLD_NOW | sys::RTLD_GLOBAL) {
            Ok(_) => vlog!("host preload: {lib}"),
            Err(e) => vlog!("host preload {lib}: {e}"),
        }
    }
}

fn print_images(img: &Image, stats: &imports::BindStats) {
    let e = &img.elf;
    println!("images:");
    println!(
        "  main  {}  base={:#x} end={:#x} entry={:#x} phnum={} kind=exec",
        e.path.display(),
        img.base,
        img.end,
        e.entry,
        e.phdrs.len()
    );
    for l in &img.loads {
        println!(
            "    LOAD {:#x} +{:#x} (file {:#x}+{:#x} @ {:#x}, anon {:#x}) {}",
            l.start, l.len as u64, l.file_off, l.file_len as u64, l.vaddr, l.anon_len as u64,
            prot_str(l.prot)
        );
    }
    for n in &e.needed {
        println!("    NEEDED {n} -> host bridge");
    }
    if let Some(t) = e.tls {
        let block = crate::image::align_up(t.memsz, t.align.max(1));
        println!(
            "    TLS vaddr={:#x} filesz={:#x} memsz={:#x} align={:#x} (block {:#x}, local-exec)",
            t.vaddr, t.filesz, t.memsz, t.align, block
        );
    } else {
        println!("    TLS: none");
    }
    println!("    stack request: {:#x}", img.stack_size());
    println!(
        "    relocs: jump_slot={} glob_dat={} abs64={} copy={} relative={} irelative={}",
        stats.jump_slot,
        stats.glob_dat,
        stats.abs64,
        stats.copy,
        stats.relative,
        stats.irelative.len()
    );
    if !stats.shim_hits.is_empty() {
        println!("    shims: {}", stats.shim_hits.join(", "));
    }
    if !stats.weak_missing.is_empty() {
        println!("    weak unresolved: {}", stats.weak_missing.join(", "));
    }
}
