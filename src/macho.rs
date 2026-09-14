//! Mach-O parser (64-bit little-endian thin slices, fat/universal containers).

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const FAT_MAGIC: u32 = 0xcafe_babe;
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;

pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub const CPU_SUBTYPE_MASK: u32 = 0x00ff_ffff;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

pub const MH_EXECUTE: u32 = 0x2;
pub const MH_DYLIB: u32 = 0x6;
pub const MH_PIE: u32 = 0x0020_0000;

pub const LC_REQ_DYLD: u32 = 0x8000_0000;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub addr: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub initprot: u32,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone)]
pub struct DylibRef {
    pub install_name: String,
    pub weak: bool,
    pub reexport: bool,
}

#[derive(Debug, Clone)]
pub struct Symtab {
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

#[derive(Debug, Clone)]
pub struct DyldInfo {
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct LinkeditData {
    pub off: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct MachO {
    pub path: PathBuf,
    /// Offset of this mach-o slice within the file (fat binaries).
    pub slice_offset: u64,
    pub filetype: u32,
    pub flags: u32,
    pub segments: Vec<Segment>,
    /// Everything but LC_ID_DYLIB, in load command order (ordinals 1-based).
    pub dylibs: Vec<DylibRef>,
    pub rpaths: Vec<String>,
    pub entry_off: Option<u64>,
    /// LC_MAIN stacksize: the main-thread stack the kernel would grant.
    pub entry_stack_size: Option<u64>,
    pub unixthread_pc: Option<u64>,
    pub symtab: Option<Symtab>,
    pub dyld_info: Option<DyldInfo>,
    pub chained_fixups: Option<LinkeditData>,
    pub exports_trie: Option<LinkeditData>,
    pub code_signature: Option<LinkeditData>,
    pub install_name: Option<String>,
}

impl MachO {
    pub fn is_exec(&self) -> bool {
        self.filetype == MH_EXECUTE
    }

    pub fn is_dylib(&self) -> bool {
        self.filetype == MH_DYLIB
    }

    pub fn pie(&self) -> bool {
        self.flags & MH_PIE != 0
    }

    /// The segment that contains the mach header (file offset 0).
    pub fn header_segment(&self) -> Option<&Segment> {
        self.segments.iter().find(|s| s.fileoff == 0 && s.filesize > 0)
    }

    pub fn text_segment(&self) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == "__TEXT")
    }

    pub fn install_name_or_path(&self) -> String {
        self.install_name
            .clone()
            .unwrap_or_else(|| self.path.display().to_string())
    }
}

fn be32(d: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(d[o..o + 4].try_into().unwrap())
}

fn be64(d: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(d[o..o + 8].try_into().unwrap())
}

fn le32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

fn le64(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

fn cstr(d: &[u8], o: usize) -> Result<String, String> {
    if o >= d.len() {
        return Err(format!("string offset {o:#x} out of bounds"));
    }
    let end = d[o..].iter().position(|&b| b == 0).ok_or("unterminated string")?;
    Ok(String::from_utf8_lossy(&d[o..o + end]).into_owned())
}

fn fixed_str(d: &[u8], o: usize, len: usize) -> String {
    let s = &d[o..o + len];
    let end = s.iter().position(|&b| b == 0).unwrap_or(len);
    String::from_utf8_lossy(&s[..end]).into_owned()
}

/// Reads a file and returns the parsed arm64 slice plus the raw file bytes.
pub fn parse_file(path: &Path) -> Result<(MachO, Arc<Vec<u8>>), String> {
    let data = Arc::new(
        std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
    );
    let (off, len) = select_slice(&data, path)?;
    let m = parse_slice(path, &data, off, len)?;
    Ok((m, data))
}

fn slice_end(data: &[u8], off: u64, len: u64) -> Result<usize, String> {
    let end = off
        .checked_add(len)
        .ok_or("slice overflow")? as usize;
    if end > data.len() {
        return Err(format!(
            "slice {off:#x}+{len:#x} exceeds file size {:#x}",
            data.len()
        ));
    }
    Ok(end)
}

fn select_slice(data: &[u8], path: &Path) -> Result<(u64, u64), String> {
    if data.len() < 8 {
        return Err(format!("{}: file too small", path.display()));
    }
    let magic = be32(data, 0);
    if magic == FAT_MAGIC || magic == FAT_MAGIC_64 {
        let is64 = magic == FAT_MAGIC_64;
        let nfat = be32(data, 4) as usize;
        let ent = if is64 { 32 } else { 20 };
        let mut arm64 = None;
        let mut arm64e = None;
        for i in 0..nfat {
            let o = 8 + i * ent;
            if o + ent > data.len() {
                return Err(format!("{}: truncated fat header", path.display()));
            }
            let cputype = be32(data, o);
            let cpusubtype = be32(data, o + 4);
            let (offset, size) = if is64 {
                (be64(data, o + 8), be64(data, o + 16))
            } else {
                (be32(data, o + 8) as u64, be32(data, o + 12) as u64)
            };
            if cputype == CPU_TYPE_ARM64 {
                match cpusubtype & CPU_SUBTYPE_MASK {
                    CPU_SUBTYPE_ARM64E => arm64e = Some((offset, size)),
                    CPU_SUBTYPE_ARM64_ALL => arm64 = Some((offset, size)),
                    _ => {}
                }
            }
        }
        if let Some((o, s)) = arm64 {
            slice_end(data, o, s)?;
            return Ok((o, s));
        }
        if arm64e.is_some() {
            return Err(format!(
                "{}: only an arm64e slice is present; v1 loads plain arm64 binaries only",
                path.display()
            ));
        }
        return Err(format!("{}: no arm64 slice in fat binary", path.display()));
    }
    if magic == MH_MAGIC_64.swap_bytes() {
        // Bytes cf fa ed fe read big-endian means a little-endian MH_MAGIC_64.
        return Ok((0, data.len() as u64));
    }
    Err(format!(
        "{}: not a Mach-O (magic {:#010x})",
        path.display(),
        magic
    ))
}

fn parse_slice(path: &Path, data: &[u8], off: u64, len: u64) -> Result<MachO, String> {
    let end = slice_end(data, off, len)?;
    let s = &data[off as usize..end];
    if s.len() < 32 || le32(s, 0) != MH_MAGIC_64 {
        return Err(format!("{}: slice is not a 64-bit Mach-O", path.display()));
    }
    let cputype = le32(s, 4);
    let cpusubtype = le32(s, 8);
    if cputype != CPU_TYPE_ARM64 {
        return Err(format!(
            "{}: cputype {cputype:#x} is not arm64",
            path.display()
        ));
    }
    if cpusubtype & CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E {
        return Err(format!(
            "{}: arm64e binaries are not supported in v1",
            path.display()
        ));
    }
    let filetype = le32(s, 12);
    let ncmds = le32(s, 16) as usize;
    let sizeofcmds = le32(s, 20) as usize;
    let flags = le32(s, 24);
    if 32 + sizeofcmds > s.len() {
        return Err(format!("{}: load commands exceed slice", path.display()));
    }

    let mut m = MachO {
        path: path.to_path_buf(),
        slice_offset: off,
        filetype,
        flags,
        segments: Vec::new(),
        dylibs: Vec::new(),
        rpaths: Vec::new(),
        entry_off: None,
        entry_stack_size: None,
        unixthread_pc: None,
        symtab: None,
        dyld_info: None,
        chained_fixups: None,
        exports_trie: None,
        code_signature: None,
        install_name: None,
    };

    let mut p = 32usize;
    for _ in 0..ncmds {
        if p + 8 > 32 + sizeofcmds {
            return Err(format!("{}: truncated load command", path.display()));
        }
        let cmd = le32(s, p);
        let cmdsize = le32(s, p + 4) as usize;
        if cmdsize < 8 || p + cmdsize > 32 + sizeofcmds {
            return Err(format!(
                "{}: bad load command size {cmdsize:#x} at {p:#x}",
                path.display()
            ));
        }
        let c = &s[p..p + cmdsize];
        match cmd {
            LC_SEGMENT_64 => {
                if cmdsize < 72 {
                    return Err("LC_SEGMENT_64 too small".into());
                }
                let name = fixed_str(c, 8, 16);
                let nsects = le32(c, 64) as usize;
                if 72 + nsects * 80 > cmdsize {
                    return Err("LC_SEGMENT_64 section overflow".into());
                }
                let mut sections = Vec::with_capacity(nsects);
                for i in 0..nsects {
                    let q = 72 + i * 80;
                    sections.push(Section {
                        name: fixed_str(c, q, 16),
                        addr: le64(c, q + 32),
                        size: le64(c, q + 40),
                    });
                }
                m.segments.push(Segment {
                    name,
                    vmaddr: le64(c, 24),
                    vmsize: le64(c, 32),
                    fileoff: le64(c, 40),
                    filesize: le64(c, 48),
                    initprot: le32(c, 60),
                    sections,
                });
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                let no = le32(c, 8) as usize;
                let name = cstr(c, no)?;
                m.dylibs.push(DylibRef {
                    install_name: name,
                    weak: cmd == LC_LOAD_WEAK_DYLIB,
                    reexport: cmd == LC_REEXPORT_DYLIB,
                });
            }
            LC_ID_DYLIB => {
                let no = le32(c, 8) as usize;
                m.install_name = Some(cstr(c, no)?);
            }
            LC_RPATH => {
                let no = le32(c, 8) as usize;
                m.rpaths.push(cstr(c, no)?);
            }
            LC_MAIN => {
                if cmdsize < 24 {
                    return Err("LC_MAIN too small".into());
                }
                m.entry_off = Some(le64(c, 8));
                m.entry_stack_size = Some(le64(c, 16));
            }
            LC_UNIXTHREAD => {
                // arm_thread_state64_t: x[29], fp, lr, sp, pc, cpsr, pad
                if cmdsize >= 16 + 264 {
                    let flavor = le32(c, 8);
                    if flavor == 6 {
                        m.unixthread_pc = Some(le64(c, 16 + 32 * 8));
                    }
                }
            }
            LC_SYMTAB => {
                m.symtab = Some(Symtab {
                    symoff: le32(c, 8),
                    nsyms: le32(c, 12),
                    stroff: le32(c, 16),
                    strsize: le32(c, 20),
                });
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                m.dyld_info = Some(DyldInfo {
                    rebase_off: le32(c, 8),
                    rebase_size: le32(c, 12),
                    bind_off: le32(c, 16),
                    bind_size: le32(c, 20),
                    weak_bind_off: le32(c, 24),
                    weak_bind_size: le32(c, 28),
                    lazy_bind_off: le32(c, 32),
                    lazy_bind_size: le32(c, 36),
                    export_off: le32(c, 40),
                    export_size: le32(c, 44),
                });
            }
            LC_DYLD_CHAINED_FIXUPS => {
                m.chained_fixups = Some(LinkeditData {
                    off: le32(c, 8),
                    size: le32(c, 12),
                });
            }
            LC_DYLD_EXPORTS_TRIE => {
                m.exports_trie = Some(LinkeditData {
                    off: le32(c, 8),
                    size: le32(c, 12),
                });
            }
            LC_CODE_SIGNATURE => {
                m.code_signature = Some(LinkeditData {
                    off: le32(c, 8),
                    size: le32(c, 12),
                });
            }
            _ => {}
        }
        p += cmdsize;
    }
    Ok(m)
}

/// Slice-relative file data (linkedit payloads, symtab, etc.).
pub fn slice_data<'a>(data: &'a [u8], slice_offset: u64, off: u32, size: u32) -> Result<&'a [u8], String> {
    if size == 0 {
        return Ok(&[]);
    }
    let start = slice_offset as usize + off as usize;
    let end = start + size as usize;
    data.get(start..end)
        .ok_or_else(|| format!("linkedit offset {off:#x}+{size:#x} out of file"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le16_reads() {
        assert_eq!(le16(&[0x34, 0x12], 0), 0x1234);
    }
}
