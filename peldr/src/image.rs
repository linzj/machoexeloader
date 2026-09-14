//! Address space reservation, section mapping, base relocation application
//! and final page protection.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::pe::{Pe, TlsDir, REL_BASED_DIR64, REL_BASED_HIGHLOW};
use crate::sys;
use crate::vlog;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImageKind {
    MainExe,
    SelfDll,
    Bridged,
}

pub struct MappedSec {
    pub name: String,
    pub addr: usize,
    pub len: usize,
    pub prot: u32,
}

pub struct Image {
    pub kind: ImageKind,
    /// Lowercase module file name ("claude.exe", "kernel32.dll").
    pub name: String,
    pub path: Option<PathBuf>,
    pub pe: Option<Pe>,
    pub base: usize,
    pub delta: i64,
    pub mapped: Vec<MappedSec>,
    pub exports: HashMap<String, crate::pe::ExportEntry>,
    pub exports_ord: HashMap<u32, crate::pe::ExportEntry>,
    /// Registry index of each import DLL, aligned with Pe::imports() order.
    pub deps: Vec<usize>,
    /// Bridged images only: the host module handle.
    pub host_handle: usize,
    pub tls: Option<TlsDir>,
    pub reloc_count: u64,
}

impl Image {
    pub fn pe(&self) -> &Pe {
        self.pe.as_ref().expect("mapped image has a parsed Pe")
    }

    pub fn addr_of(&self, rva: u32) -> usize {
        self.base + rva as usize
    }

    pub fn pdata_addr(&self) -> Option<(usize, u32)> {
        self.pe.as_ref().and_then(|p| p.pdata()).map(|(rva, n)| (self.addr_of(rva), n))
    }

    /// Reserve address space, map headers + sections, apply relocations.
    /// Everything is committed read/write; final protections come later via
    /// reprotect() so the import/TLS passes can still write.
    /// `force_rebase` reserves (and abandons) the linked base first so the
    /// image always lands elsewhere: exercises the relocation path.
    pub fn map(pe: Pe, kind: ImageKind, name: String, force_rebase: bool) -> Result<Image, String> {
        let span = pe.size_of_image as usize;
        let preferred = pe.image_base as usize;
        if force_rebase {
            if let Some(p) = sys::reserve(preferred, span) {
                vlog!("{}: blocking preferred base {:#x} (forced rebase)", name, p as usize);
            }
            let p = sys::reserve(0, span).ok_or_else(|| {
                format!(
                    "{}: cannot reserve {span:#x} bytes of address space",
                    pe.path.display()
                )
            })?;
            return Image::map_at(pe, kind, name, p as usize);
        }

        let (base, fallback) = match sys::reserve(preferred, span) {
            Some(p) if p as usize == preferred => (preferred, false),
            Some(p) => {
                // VirtualAlloc rounded somewhere else; drop it and pick freely.
                sys::release(p as usize, span);
                (0, true)
            }
            None => (0, true),
        };
        let base = if fallback {
            if !pe.has_relocs() {
                return Err(format!(
                    "{}: ImageBase {preferred:#x} is unavailable and the image has no base relocations",
                    pe.path.display()
                ));
            }
            match sys::reserve(0, span) {
                Some(p) => p as usize,
                None => {
                    return Err(format!(
                        "{}: cannot reserve {span:#x} bytes of address space",
                        pe.path.display()
                    ));
                }
            }
        } else {
            base
        };
        Image::map_at(pe, kind, name, base)
    }

    fn map_at(pe: Pe, kind: ImageKind, name: String, base: usize) -> Result<Image, String> {
        let span = pe.size_of_image as usize;
        let page = sys::page_size();
        let preferred = pe.image_base as usize;

        sys::commit(base, span)?;

        // Copy headers and raw section bytes; the commit zero-fills the rest.
        let data = pe.data.as_slice();
        let hdr = (pe.size_of_headers as usize).min(data.len());
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), base as *mut u8, hdr);
        }
        let mut mapped = Vec::new();
        for s in &pe.sections {
            if s.raw_size == 0 && s.vsize == 0 {
                continue;
            }
            if s.raw_size > 0 {
                let off = s.raw_off as usize;
                off.checked_add(s.raw_size as usize)
                    .filter(|&e| e <= data.len())
                    .ok_or_else(|| {
                        format!(
                            "{}: section {} raw data {:#x}+{:#x} out of file",
                            pe.path.display(),
                            s.name,
                            s.raw_off,
                            s.raw_size
                        )
                    })?;
                if s.va as usize + s.raw_size as usize > span {
                    return Err(format!(
                        "{}: section {} raw data outside SizeOfImage",
                        pe.path.display(),
                        s.name
                    ));
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr().add(off),
                        (base + s.va as usize) as *mut u8,
                        s.raw_size as usize,
                    );
                }
            }
            let len = sys::round_up(s.span() as usize, page).min(sys::round_up(span, page) - s.va as usize);
            mapped.push(MappedSec {
                name: s.name.clone(),
                addr: base + s.va as usize,
                len,
                prot: pe.section_prot(s),
            });
        }

        let delta = base as i64 - pe.image_base as i64;
        let mut reloc_count = 0u64;
        if delta != 0 {
            if !pe.has_relocs() {
                return Err(format!(
                    "{}: loaded away from ImageBase but has no relocations",
                    pe.path.display()
                ));
            }
            for (rva, typ) in pe.relocations()? {
                let a = base + rva as usize;
                if rva as usize + 8 > span {
                    return Err(format!(
                        "{}: relocation at rva {rva:#x} outside image",
                        pe.path.display()
                    ));
                }
                match typ {
                    REL_BASED_DIR64 => unsafe {
                        let v = *(a as *const u64);
                        *(a as *mut u64) = v.wrapping_add(delta as u64);
                    },
                    REL_BASED_HIGHLOW => unsafe {
                        let v = *(a as *const u32);
                        *(a as *mut u32) = v.wrapping_add(delta as u32);
                    },
                    other => {
                        return Err(format!(
                            "{}: unsupported relocation type {other} at rva {rva:#x}",
                            pe.path.display()
                        ));
                    }
                }
                reloc_count += 1;
            }
        }

        vlog!(
            "{}: mapped at {:#x} (preferred {:#x}, delta {delta:+#x}), {} sections, {} relocs applied, \
             align {:#x}/{:#x}, subsystem {:#x}",
            name,
            base,
            preferred,
            mapped.len(),
            reloc_count,
            pe.section_alignment,
            pe.file_alignment,
            pe.subsystem
        );

        let (by_name, by_ord) = pe.exports()?;
        let exports = by_name.into_iter().collect();
        let exports_ord = by_ord.into_iter().collect();

        Ok(Image {
            kind,
            name,
            path: Some(pe.path.clone()),
            tls: pe.tls()?,
            pe: Some(pe),
            base,
            delta,
            mapped,
            exports,
            exports_ord,
            deps: Vec::new(),
            host_handle: 0,
            reloc_count,
        })
    }

    pub fn new_bridged(name: String, host_handle: usize) -> Image {
        Image {
            kind: ImageKind::Bridged,
            name,
            path: None,
            pe: None,
            base: 0,
            delta: 0,
            mapped: Vec::new(),
            exports: HashMap::new(),
            exports_ord: HashMap::new(),
            deps: Vec::new(),
            host_handle,
            tls: None,
            reloc_count: 0,
        }
    }

    /// Apply the sections' declared final protections (headers read-only).
    pub fn reprotect(&self) -> Result<(), String> {
        if self.kind == ImageKind::Bridged {
            return Ok(());
        }
        let pe = self.pe();
        let page = sys::page_size();
        let span = pe.size_of_image as usize;
        let hdr_len = sys::round_up(pe.size_of_headers as usize, page).min(sys::round_up(span, page));
        sys::protect(self.base, hdr_len, sys::PAGE_READONLY)?;
        for sec in &self.mapped {
            if sec.len == 0 {
                continue;
            }
            sys::protect(sec.addr, sec.len, sec.prot)?;
            vlog!("  {:<10} {:#x} -> {:#x}", sec.name, sec.addr, sec.prot);
        }
        Ok(())
    }
}
