//! Address-space reservation, segment mapping and the image registry.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::macho::MachO;
use crate::resolve::Export;
use crate::sys;
use crate::vlog;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ImageKind {
    MainExec,
    Dylib,
    /// A system dylib (dyld shared cache) borrowed from the host process.
    SystemBridged,
}

pub struct MappedSeg {
    pub name: String,
    pub addr: usize,
    /// Total runtime extent (file part + zero-fill tail), page rounded.
    pub len: usize,
    pub initprot: u32,
    /// Protection actually used for the initial mmap. macOS 26 rejects
    /// PROT_EXEC in the initial mapping of a file, so exec is acquired with a
    /// later mprotect; __DATA* may be mapped writable for fixups.
    pub map_prot: i32,
}

pub struct Image {
    pub kind: ImageKind,
    /// Install name for dylibs, path for the main executable.
    pub install_name: String,
    pub path: Option<PathBuf>,
    pub macho: Option<MachO>,
    pub file: Option<Arc<Vec<u8>>>,
    /// vmaddr -> runtime address is `vmaddr + slide`.
    pub slide: i64,
    /// vmaddr of the segment containing the mach header.
    pub header_vmaddr: u64,
    pub mapped: Vec<MappedSeg>,
    /// Dependency images in LC_LOAD_DYLIB order (ordinal N -> deps[N-1]).
    pub deps: Vec<usize>,
    pub exports: HashMap<String, Export>,
    pub init_funcs: Vec<usize>,
    /// dlopen handle for SystemBridged images.
    pub dl_handle: usize,
}

impl Image {
    pub fn addr_of(&self, vmaddr: u64) -> usize {
        (vmaddr as i64 + self.slide) as usize
    }

    /// Runtime address of the mach header (chained-fixup "image base").
    pub fn base(&self) -> usize {
        self.addr_of(self.header_vmaddr)
    }

    pub fn macho(&self) -> &MachO {
        self.macho.as_ref().expect("image has no mach-o")
    }

    pub fn data(&self, off: u32, size: u32) -> Result<&[u8], String> {
        let m = self.macho();
        let file = self.file.as_ref().ok_or("image has no file data")?;
        crate::macho::slice_data(file, m.slice_offset, off, size)
    }

    /// Apply final segment protections: __TEXT gets its r-x back, __DATA_CONST
    /// goes read-only again after fixups (same dance dyld performs).
    pub fn reprotect(&self) -> Result<(), String> {
        for seg in &self.mapped {
            let want = umask_prot(seg.initprot);
            if seg.map_prot != want {
                sys::protect(seg.addr, seg.len, want)?;
                vlog!(
                    "  {:<16} {:#x} -> {}",
                    seg.name,
                    seg.addr,
                    prot_str(want)
                );
            }
        }
        Ok(())
    }
}

fn umask_prot(prot: u32) -> i32 {
    (prot & 0x7) as i32
}

fn round_up(v: u64, align: u64) -> u64 {
    v.div_ceil(align) * align
}

/// A stand-in for a missing weak dependency: binds through it resolve like
/// missing symbols instead of shifting later ordinals.
pub fn new_placeholder(install_name: &str) -> Image {
    Image {
        kind: ImageKind::SystemBridged,
        install_name: install_name.to_string(),
        path: None,
        macho: None,
        file: None,
        slide: 0,
        header_vmaddr: 0,
        mapped: Vec::new(),
        deps: Vec::new(),
        exports: HashMap::new(),
        init_funcs: Vec::new(),
        dl_handle: 0,
    }
}

pub fn new_bridged(install_name: &str) -> Result<Image, String> {
    vlog!("bridging system library {install_name}");
    let handle = sys::dlopen_path(install_name)?;
    Ok(Image {
        kind: ImageKind::SystemBridged,
        install_name: install_name.to_string(),
        path: Some(PathBuf::from(install_name)),
        macho: None,
        file: None,
        slide: 0,
        header_vmaddr: 0,
        mapped: Vec::new(),
        deps: Vec::new(),
        exports: HashMap::new(),
        init_funcs: Vec::new(),
        dl_handle: handle as usize,
    })
}

/// Reserve address space for the image's segments and map them in.
///
/// __TEXT stays a file-backed mapping so the code signature remains valid and
/// its pages can be executed by the kernel; __DATA* segments are mapped
/// writable while fixups run (COW, the file is untouched).
pub fn map_image(m: MachO, file: &Arc<Vec<u8>>, kind: ImageKind, install_name: String) -> Result<Image, String> {
    let page = sys::page_size() as u64;
    let header_vmaddr = m
        .header_segment()
        .ok_or("no segment contains the mach header (file offset 0)")?
        .vmaddr;

    let mut min_vm = u64::MAX;
    let mut max_end = 0u64;
    for s in &m.segments {
        if s.name == "__PAGEZERO" || s.vmsize == 0 {
            continue;
        }
        min_vm = min_vm.min(s.vmaddr);
        max_end = max_end.max(s.vmaddr + round_up(s.vmsize, page));
    }
    if min_vm == u64::MAX {
        return Err(format!("{}: no loadable segments", m.path.display()));
    }
    if min_vm != header_vmaddr {
        return Err(format!(
            "{}: header segment vmaddr {header_vmaddr:#x} != lowest vmaddr {min_vm:#x} (unsupported layout)",
            m.path.display()
        ));
    }
    if min_vm % page != 0 {
        return Err(format!("{}: vmaddr {min_vm:#x} not page aligned", m.path.display()));
    }

    // Validate page congruence before mapping anything.
    for s in &m.segments {
        if s.name == "__PAGEZERO" || s.vmsize == 0 {
            continue;
        }
        if s.vmaddr % page != 0 {
            return Err(format!("{}: segment {} vmaddr {:#x} not page aligned", m.path.display(), s.name, s.vmaddr));
        }
        if s.filesize > 0 && (s.fileoff % page) != (s.vmaddr % page) {
            return Err(format!(
                "{}: segment {} fileoff {:#x} not congruent with vmaddr {:#x}",
                m.path.display(),
                s.name,
                s.fileoff,
                s.vmaddr
            ));
        }
    }

    let span = (max_end - min_vm) as usize;
    let reservation = sys::reserve(span + page as usize)?;
    let base = (reservation as usize + page as usize - 1) & !(page as usize - 1);
    let slide = base as i64 - min_vm as i64;
    vlog!(
        "{}: base {base:#x} slide {slide:#x} span {span:#x}",
        install_name
    );

    let f = std::fs::File::open(&m.path)
        .map_err(|e| format!("cannot open {} for mapping: {e}", m.path.display()))?;
    use std::os::unix::io::AsRawFd;
    let fd = f.as_raw_fd();

    let needs_fixups = m.chained_fixups.is_some() || m.dyld_info.is_some();
    let mut mapped = Vec::new();
    for s in &m.segments {
        if s.name == "__PAGEZERO" || s.vmsize == 0 {
            continue;
        }
        let addr = (s.vmaddr as i64 + slide) as usize;
        let mut prot = umask_prot(s.initprot);
        // macOS 26 (XNU): a PROT_EXEC file mapping is rejected outright
        // (EPERM), even MAP_FIXED over our own reservation. dyld-style fix:
        // map without exec and mprotect r-x afterwards.
        if prot & sys::PROT_EXEC != 0 {
            prot &= !sys::PROT_EXEC;
        }
        if needs_fixups && s.name.starts_with("__DATA") && (prot & sys::PROT_WRITE) == 0 {
            prot |= sys::PROT_WRITE;
        }
        if s.filesize > 0 {
            let off = m.slice_offset + s.fileoff;
            sys::map_file_fixed(addr, s.filesize as usize, prot, fd, off)?;
        }
        let file_pages_end = round_up(s.filesize, page);
        if s.vmsize > file_pages_end {
            let tail_addr = addr + file_pages_end as usize;
            let tail_len = (round_up(s.vmsize, page) - file_pages_end) as usize;
            sys::map_anon_fixed(tail_addr, tail_len, prot)?;
        }
        vlog!(
            "  {:<16} vmaddr {:#012x} size {:#08x} -> {addr:#014x} {}",
            s.name,
            s.vmaddr,
            s.vmsize,
            prot_str(prot)
        );
        mapped.push(MappedSeg {
            name: s.name.clone(),
            addr,
            len: round_up(s.vmsize, page) as usize,
            initprot: s.initprot,
            map_prot: prot,
        });
    }

    Ok(Image {
        kind,
        install_name,
        path: Some(m.path.clone()),
        macho: Some(m),
        file: Some(file.clone()),
        slide,
        header_vmaddr,
        mapped,
        deps: Vec::new(),
        exports: HashMap::new(),
        init_funcs: Vec::new(),
        dl_handle: 0,
    })
}

/// Collects initializers. Modern binaries (chained fixups era) list them as
/// 32-bit offsets from the image base in __TEXT,__init_offsets; older ones use
/// rebased pointers in __DATA*.__mod_init_func. Call after the fixup pass.
pub fn collect_init_funcs(img: &Image) -> Vec<usize> {
    let Some(m) = &img.macho else { return Vec::new() };
    let mut out = Vec::new();
    if let Some(text) = m.segments.iter().find(|s| s.name == "__TEXT") {
        for sec in &text.sections {
            if sec.name != "__init_offsets" || sec.size < 4 {
                continue;
            }
            let addr = img.addr_of(sec.addr);
            for i in 0..(sec.size / 4) as usize {
                let off = unsafe { *((addr + i * 4) as *const i32) };
                out.push((img.base() as i64 + off as i64) as usize);
            }
        }
    }
    for s in &m.segments {
        if !s.name.starts_with("__DATA") {
            continue;
        }
        for sec in &s.sections {
            if sec.name != "__mod_init_func" || sec.size == 0 {
                continue;
            }
            let addr = img.addr_of(sec.addr);
            for i in 0..(sec.size / 8) as usize {
                let p = unsafe { *((addr + i * 8) as *const usize) };
                if p != 0 {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn prot_str(prot: i32) -> String {
    let mut s = String::new();
    s.push(if prot & sys::PROT_READ != 0 { 'r' } else { '-' });
    s.push(if prot & sys::PROT_WRITE != 0 { 'w' } else { '-' });
    s.push(if prot & sys::PROT_EXEC != 0 { 'x' } else { '-' });
    s
}
