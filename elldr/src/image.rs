//! Address-space reservation and segment mapping for the target image.
//! Only ET_EXEC images are supported, so virtual addresses are absolute and
//! the image must land exactly where it was linked.

#![allow(dead_code)]

use crate::elf::{ElfFile, PT_LOAD};
use crate::sys;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImageKind {
    Main,
}

#[derive(Clone, Copy, Debug)]
pub struct LoadSeg {
    /// Page-aligned start of the mapping.
    pub start: u64,
    pub len: usize,
    pub file_off: u64,
    pub file_len: usize,
    pub anon_len: usize,
    pub prot: i32,
    pub vaddr: u64,
    pub memsz: u64,
}

pub fn align_down(v: u64, a: u64) -> u64 {
    v & !(a - 1)
}

pub fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn flags_to_prot(flags: u32) -> i32 {
    let mut p = 0;
    if flags & crate::elf::PF_R != 0 {
        p |= sys::PROT_READ;
    }
    if flags & crate::elf::PF_W != 0 {
        p |= sys::PROT_WRITE;
    }
    if flags & crate::elf::PF_X != 0 {
        p |= sys::PROT_EXEC;
    }
    p
}

pub fn prot_str(p: i32) -> String {
    let mut s = String::with_capacity(3);
    s.push(if p & sys::PROT_READ != 0 { 'r' } else { '-' });
    s.push(if p & sys::PROT_WRITE != 0 { 'w' } else { '-' });
    s.push(if p & sys::PROT_EXEC != 0 { 'x' } else { '-' });
    s
}

pub struct Image {
    pub elf: ElfFile,
    pub kind: ImageKind,
    pub base: u64,
    pub end: u64,
    pub loads: Vec<LoadSeg>,
}

impl Image {
    /// Reserve the image span and map every PT_LOAD segment at its linked
    /// address (file-backed with MAP_FIXED, zero-fill tails anonymous).
    pub fn map(elf: ElfFile) -> Result<Image, String> {
        let page = sys::page_size() as u64;
        let loads: Vec<_> = elf
            .phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .cloned()
            .collect();
        if loads.is_empty() {
            return Err(format!("{}: no PT_LOAD segments", elf.path.display()));
        }
        let base = loads
            .iter()
            .map(|p| align_down(p.p_vaddr, page))
            .min()
            .unwrap();
        let end = loads
            .iter()
            .map(|p| align_up(p.p_vaddr + p.p_memsz, page))
            .max()
            .unwrap();
        if base < 0x10000 {
            return Err(format!(
                "{}: PT_LOAD below mmap_min_addr ({base:#x})",
                elf.path.display()
            ));
        }

        // The loader itself must be PIE: a fixed low image would collide with
        // the target span below.
        let at_phdr = sys::auxval(sys::AT_PHDR);
        if at_phdr != 0 && at_phdr < 0x1_0000_0000 {
            return Err(format!(
                "elldr itself is not PIE (AT_PHDR={at_phdr:#x}); it must be linked position-independent"
            ));
        }

        sys::reserve_fixed(base as usize, (end - base) as usize)
            .map_err(|e| format!("{}: {e}", elf.path.display()))?;

        let fd = {
            use std::os::unix::io::AsRawFd;
            elf.file.as_raw_fd()
        };
        let mut mapped = Vec::with_capacity(loads.len());
        for p in &loads {
            let start = align_down(p.p_vaddr, page);
            let off = align_down(p.p_offset, page);
            let rel = p.p_vaddr - start;
            let prot = flags_to_prot(p.p_flags);
            let mut file_len = 0usize;
            if p.p_filesz > 0 {
                let flen = align_up(rel + p.p_filesz, page);
                sys::map_file_fixed(start as usize, flen as usize, prot, fd, off as i64)
                    .map_err(|e| format!("{}: {e}", elf.path.display()))?;
                file_len = flen as usize;
            }
            let full = align_up(rel + p.p_memsz, page) as usize;
            let anon_len = full.saturating_sub(file_len);
            if anon_len > 0 {
                let astart = start as usize + file_len;
                sys::map_anon_fixed(astart, anon_len, prot)
                    .map_err(|e| format!("{}: {e}", elf.path.display()))?;
            }
            mapped.push(LoadSeg {
                start,
                len: full,
                file_off: off,
                file_len,
                anon_len,
                prot,
                vaddr: p.p_vaddr,
                memsz: p.p_memsz,
            });
        }

        Ok(Image {
            elf,
            kind: ImageKind::Main,
            base,
            end,
            loads: mapped,
        })
    }

    /// ET_EXEC: VA == runtime address.
    pub fn addr_of(&self, va: u64) -> usize {
        va as usize
    }

    pub fn contains(&self, addr: usize) -> bool {
        let a = addr as u64;
        a >= self.base && a < self.end
    }

    pub fn entry_addr(&self) -> usize {
        self.elf.entry as usize
    }

    /// PT_GNU_STACK request, floored at 8 MiB.
    pub fn stack_size(&self) -> usize {
        (self.elf.stack_size as usize).max(8 * 1024 * 1024)
    }

    pub fn tls(&self) -> Option<crate::elf::TlsInfo> {
        self.elf.tls
    }

    /// Phdrs as they appear in the mapped image (for dl_iterate_phdr).
    pub fn phdr_addr(&self) -> usize {
        (self.base + self.elf.phoff) as usize
    }

    pub fn prot_at(&self, va: u64) -> i32 {
        for l in &self.loads {
            if va >= l.start && va < l.start + l.len as u64 {
                return l.prot;
            }
        }
        0
    }
}
