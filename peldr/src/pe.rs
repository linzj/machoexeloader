//! PE32+ parsing: headers, sections, data directories, imports, exports,
//! base relocations and the TLS directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;

const DOS_MAGIC: u16 = 0x5A4D;
const NT_MAGIC: u32 = 0x0000_4550;
const OPT_MAGIC_64: u16 = 0x020B;
const MACHINE_AMD64: u16 = 0x8664;

pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_EXCEPTION: usize = 3;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_TLS: usize = 9;
pub const DIR_DELAY_IMPORT: usize = 13;

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub const FILE_EXECUTABLE: u16 = 0x0002;
pub const FILE_DLL: u16 = 0x2000;

pub const REL_BASED_ABSOLUTE: u8 = 0;
pub const REL_BASED_HIGHLOW: u8 = 3;
pub const REL_BASED_DIR64: u8 = 10;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub va: u32,
    pub vsize: u32,
    pub raw_off: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn span(&self) -> u32 {
        self.vsize.max(self.raw_size)
    }
    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.va && rva < self.va.wrapping_add(self.span())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportEntry {
    Rva(u32),
    Forwarder(String),
}

#[derive(Clone, Debug)]
pub enum ImportName {
    Name(String),
    Ordinal(u16),
}

#[derive(Clone, Debug)]
pub struct ImportDll {
    pub name: String,
    pub funcs: Vec<ImportName>,
    /// FirstThunk: where resolved addresses are written.
    pub iat_rva: u32,
}

#[derive(Clone, Debug)]
pub struct TlsDir {
    pub template_rva: u32,
    pub template_size: u32,
    pub zero_fill: u32,
    /// AddressOfIndex (VA converted to RVA): the DWORD the loader writes the
    /// module's TLS index into.
    pub index_rva: u32,
    /// AddressOfCallBacks (array of function pointers, NULL terminated).
    pub callbacks_rva: Option<u32>,
}

pub struct Pe {
    pub path: PathBuf,
    pub data: Arc<Vec<u8>>,
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub characteristics: u16,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub sections: Vec<Section>,
    pub dirs: [(u32, u32); 16],
}

impl Pe {
    pub fn parse_file(path: &Path) -> Result<Pe, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Pe::parse(path.to_path_buf(), Arc::new(data))
    }

    pub fn parse(path: PathBuf, data: Arc<Vec<u8>>) -> Result<Pe, String> {
        let ps = path.display().to_string();
        let build = move || -> Result<Pe, String> {
            let b = data.as_slice();
            if rd_u16(b, 0)? != DOS_MAGIC {
                return Err("not a PE file (missing MZ)".into());
            }
            let e_lfanew = rd_u32(b, 0x3C)? as usize;
            if rd_u32(b, e_lfanew)? != NT_MAGIC {
                return Err(format!("bad NT signature at {e_lfanew:#x}"));
            }
            let machine = rd_u16(b, e_lfanew + 4)?;
            let nsec = rd_u16(b, e_lfanew + 6)?;
            let opt_size = rd_u16(b, e_lfanew + 20)? as usize;
            let chars = rd_u16(b, e_lfanew + 22)?;
            if machine == 0x014C {
                return Err("32-bit PE is not supported (x86_64 only)".into());
            }
            if machine == 0xAA64 {
                return Err("ARM64 PE is not supported (x86_64 only)".into());
            }
            if machine != MACHINE_AMD64 {
                return Err(format!("unsupported machine {machine:#x}"));
            }
            let opt = e_lfanew + 24;
            if rd_u16(b, opt)? != OPT_MAGIC_64 {
                return Err("not a PE32+ optional header".into());
            }
            let entry_rva = rd_u32(b, opt + 16)?;
            let image_base = rd_u64(b, opt + 24)?;
            let section_alignment = rd_u32(b, opt + 32)?;
            let file_alignment = rd_u32(b, opt + 36)?;
            let size_of_image = rd_u32(b, opt + 56)?;
            let size_of_headers = rd_u32(b, opt + 60)?;
            let subsystem = rd_u16(b, opt + 68)?;
            let dll_characteristics = rd_u16(b, opt + 70)?;
            let stack_reserve = rd_u64(b, opt + 72)?;
            let stack_commit = rd_u64(b, opt + 80)?;
            let num_dirs = rd_u32(b, opt + 108)?;
            let mut dirs = [(0u32, 0u32); 16];
            for (i, d) in dirs.iter_mut().enumerate() {
                if (i as u32) < num_dirs {
                    *d = (rd_u32(b, opt + 112 + i * 8)?, rd_u32(b, opt + 116 + i * 8)?);
                }
            }
            let sec_off = opt + opt_size;
            let mut sections = Vec::with_capacity(nsec as usize);
            for i in 0..nsec as usize {
                let o = sec_off + i * 40;
                let name_bytes = b
                    .get(o..o + 8)
                    .ok_or_else(|| format!("section {i} header out of file"))?;
                let end = name_bytes.iter().position(|&c| c == 0).unwrap_or(8);
                let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
                sections.push(Section {
                    name,
                    vsize: rd_u32(b, o + 8)?,
                    va: rd_u32(b, o + 12)?,
                    raw_size: rd_u32(b, o + 16)?,
                    raw_off: rd_u32(b, o + 20)?,
                    characteristics: rd_u32(b, o + 36)?,
                });
            }
            let pe = Pe {
                path,
                data,
                image_base,
                entry_rva,
                size_of_image,
                size_of_headers,
                section_alignment,
                file_alignment,
                subsystem,
                dll_characteristics,
                characteristics: chars,
                stack_reserve,
                stack_commit,
                sections,
                dirs,
            };
            if pe.size_of_image == 0 {
                return Err("SizeOfImage is zero".into());
            }
            Ok(pe)
        };
        build().map_err(|e| format!("{ps}: {e}"))
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & FILE_DLL != 0
    }

    pub fn is_exe(&self) -> bool {
        self.characteristics & FILE_EXECUTABLE != 0 && !self.is_dll()
    }

    pub fn has_relocs(&self) -> bool {
        let (rva, size) = self.dirs[DIR_BASERELOC];
        rva != 0 && size >= 8
    }

    pub fn rva2off(&self, rva: u32) -> Result<usize, String> {
        if rva < self.size_of_headers {
            return Ok(rva as usize);
        }
        for s in &self.sections {
            if s.contains(rva) {
                let off = s.raw_off + (rva - s.va);
                if (off as usize) < self.data.len() {
                    return Ok(off as usize);
                }
                return Err(format!("rva {rva:#x} past EOF"));
            }
        }
        Err(format!("rva {rva:#x} is not backed by any section"))
    }

    pub fn at(&self, rva: u32, size: usize) -> Result<&[u8], String> {
        let o = self.rva2off(rva)?;
        self.data
            .get(o..o + size)
            .ok_or_else(|| format!("rva {rva:#x}+{size:#x} out of file"))
    }

    fn cstr_at(&self, rva: u32, max: usize) -> Result<String, String> {
        let o = self.rva2off(rva)?;
        let b = self.data.as_slice();
        let mut end = o;
        let lim = (o + max).min(b.len());
        while end < lim && b[end] != 0 {
            end += 1;
        }
        if end == lim {
            return Err(format!("unterminated string at rva {rva:#x}"));
        }
        Ok(String::from_utf8_lossy(&b[o..end]).into_owned())
    }

    // ---- imports -----------------------------------------------------------

    pub fn imports(&self) -> Result<Vec<ImportDll>, String> {
        let (rva, size) = self.dirs[DIR_IMPORT];
        if rva == 0 || size == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let count = (size / 20) as usize;
        for i in 0..count.min(512) {
            let o = rva + (i * 20) as u32;
            let desc = self.at(o, 20)?;
            let ilt = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
            let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]);
            let iat = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);
            if ilt == 0 && name_rva == 0 && iat == 0 {
                break;
            }
            let name = self.cstr_at(name_rva, 512)?;
            let thunks_rva = if ilt != 0 { ilt } else { iat };
            let funcs = self.walk_thunks(thunks_rva)?;
            out.push(ImportDll { name, funcs, iat_rva: iat });
        }
        Ok(out)
    }

    fn walk_thunks(&self, rva: u32) -> Result<Vec<ImportName>, String> {
        let mut funcs = Vec::new();
        for i in 0..65536u32 {
            let e = u64::from_le_bytes(self.at(rva + i * 8, 8)?.try_into().unwrap());
            if e == 0 {
                break;
            }
            if e & 0x8000_0000_0000_0000 != 0 {
                funcs.push(ImportName::Ordinal((e & 0xFFFF) as u16));
            } else {
                let name_rva = (e & 0x7FFF_FFFF) as u32;
                // u16 hint at name_rva, then the name
                let name = self.cstr_at(name_rva + 2, 512)?;
                funcs.push(ImportName::Name(name));
            }
        }
        Ok(funcs)
    }

    /// Delay-load imports (parsed for diagnostics/dependency awareness only;
    /// resolution is left to the image's own delay-load helper).
    pub fn delay_imports(&self) -> Vec<ImportDll> {
        let (rva, size) = self.dirs[DIR_DELAY_IMPORT];
        if rva == 0 || size == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let count = (size / 32) as usize;
        for i in 0..count.min(256) {
            let desc = match self.at(rva + (i * 32) as u32, 32) {
                Ok(d) => d,
                Err(_) => break,
            };
            let name_rva = u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]]);
            let iat = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]);
            let int = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);
            if name_rva == 0 && int == 0 && iat == 0 {
                break;
            }
            let name = match self.cstr_at(name_rva, 512) {
                Ok(n) => n,
                Err(_) => break,
            };
            let funcs = match self.walk_thunks(if int != 0 { int } else { iat }) {
                Ok(f) => f,
                Err(_) => Vec::new(),
            };
            out.push(ImportDll { name, funcs, iat_rva: iat });
        }
        out
    }

    // ---- exports -----------------------------------------------------------

    pub fn exports(&self) -> Result<(Vec<(String, ExportEntry)>, Vec<(u32, ExportEntry)>), String> {
        let (rva, size) = self.dirs[DIR_EXPORT];
        if rva == 0 || size == 0 {
            return Ok((Vec::new(), Vec::new()));
        }
        let d = self.at(rva, 40)?;
        let base = u32::from_le_bytes([d[16], d[17], d[18], d[19]]);
        let num_funcs = u32::from_le_bytes([d[20], d[21], d[22], d[23]]);
        let num_names = u32::from_le_bytes([d[24], d[25], d[26], d[27]]);
        let funcs_rva = u32::from_le_bytes([d[28], d[29], d[30], d[31]]);
        let names_rva = u32::from_le_bytes([d[32], d[33], d[34], d[35]]);
        let ords_rva = u32::from_le_bytes([d[36], d[37], d[38], d[39]]);
        if num_funcs > 0x10_0000 || num_names > 0x10_0000 {
            return Err(format!("unreasonable export counts ({num_funcs}/{num_names})"));
        }
        let entry_at = |func_rva: u32| -> Result<ExportEntry, String> {
            if func_rva >= rva && func_rva < rva + size {
                Ok(ExportEntry::Forwarder(self.cstr_at(func_rva, 512)?))
            } else {
                Ok(ExportEntry::Rva(func_rva))
            }
        };
        let mut by_name = Vec::new();
        for i in 0..num_names {
            let name_rva = rd_u32(self.data.as_slice(), self.rva2off(names_rva + i * 4)?)?;
            let ord = rd_u16(self.data.as_slice(), self.rva2off(ords_rva + i * 2)?)? as u32;
            if ord >= num_funcs {
                continue;
            }
            let func_rva = rd_u32(self.data.as_slice(), self.rva2off(funcs_rva + ord * 4)?)?;
            let name = self.cstr_at(name_rva, 512)?;
            by_name.push((name, entry_at(func_rva)?));
        }
        let mut by_ord = Vec::new();
        for i in 0..num_funcs {
            let func_rva = rd_u32(self.data.as_slice(), self.rva2off(funcs_rva + i * 4)?)?;
            if func_rva == 0 {
                continue;
            }
            by_ord.push((base.wrapping_add(i), entry_at(func_rva)?));
        }
        Ok((by_name, by_ord))
    }

    // ---- relocations -------------------------------------------------------

    pub fn relocations(&self) -> Result<Vec<(u32, u8)>, String> {
        let (rva, size) = self.dirs[DIR_BASERELOC];
        if rva == 0 || size == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut off = 0u32;
        while off + 8 <= size {
            let hdr = self.at(rva + off, 8)?;
            let page = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
            let bsize = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            if bsize < 8 || bsize % 2 != 0 || off + bsize > size {
                return Err(format!("bad relocation block at offset {off:#x} (size {bsize:#x})"));
            }
            let entries = (bsize - 8) / 2;
            let body = self.at(rva + off + 8, (entries * 2) as usize)?;
            for k in 0..entries as usize {
                let e = u16::from_le_bytes([body[k * 2], body[k * 2 + 1]]);
                let typ = (e >> 12) as u8;
                let ofs = (e & 0x0FFF) as u32;
                if typ != REL_BASED_ABSOLUTE {
                    out.push((page + ofs, typ));
                }
            }
            off += bsize;
        }
        Ok(out)
    }

    // ---- TLS ---------------------------------------------------------------

    pub fn tls(&self) -> Result<Option<TlsDir>, String> {
        let (rva, size) = self.dirs[DIR_TLS];
        if rva == 0 || size == 0 {
            return Ok(None);
        }
        let d = self.at(rva, 40)?;
        let start = u64::from_le_bytes(d[0..8].try_into().unwrap());
        let end = u64::from_le_bytes(d[8..16].try_into().unwrap());
        let index = u64::from_le_bytes(d[16..24].try_into().unwrap());
        let cbs = u64::from_le_bytes(d[24..32].try_into().unwrap());
        let zero_fill = u32::from_le_bytes(d[32..36].try_into().unwrap());
        let to_rva = |va: u64| -> Result<u32, String> {
            if va < self.image_base {
                return Err(format!("TLS VA {va:#x} below ImageBase"));
            }
            Ok((va - self.image_base) as u32)
        };
        let template_size = if end >= start { (end - start) as u32 } else { 0 };
        Ok(Some(TlsDir {
            template_rva: if template_size > 0 { to_rva(start)? } else { 0 },
            template_size,
            zero_fill,
            index_rva: if index != 0 { to_rva(index)? } else { 0 },
            callbacks_rva: if cbs != 0 { Some(to_rva(cbs)?) } else { None },
        }))
    }

    pub fn pdata(&self) -> Option<(u32, u32)> {
        let (rva, size) = self.dirs[DIR_EXCEPTION];
        if rva == 0 || size == 0 {
            return None;
        }
        Some((rva, size / 12))
    }

    /// Map PE section characteristics to the final page protection.
    pub fn section_prot(&self, s: &Section) -> u32 {
        let x = s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let w = s.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        match (x, w) {
            (true, true) => super::sys::PAGE_EXECUTE_READWRITE,
            (true, false) => super::sys::PAGE_EXECUTE_READ,
            (false, true) => super::sys::PAGE_READWRITE,
            (false, false) => super::sys::PAGE_READONLY,
        }
    }
}

fn rd_u16(b: &[u8], o: usize) -> Result<u16, String> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("truncated header at {o:#x}"))
}

fn rd_u32(b: &[u8], o: usize) -> Result<u32, String> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("truncated header at {o:#x}"))
}

fn rd_u64(b: &[u8], o: usize) -> Result<u64, String> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("truncated header at {o:#x}"))
}
