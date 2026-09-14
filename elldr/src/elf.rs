//! ELF64 (x86_64, ET_EXEC) parsing: program headers, PT_TLS, PT_GNU_STACK,
//! the dynamic table, dynsym/dynstr, symbol versions and RELA tables.
//! Everything is parsed from one read-only mmap of the file.

// Full named-constant surface for the formats we parse; not all is consumed.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub const ET_EXEC: u16 = 2;
pub const EM_X86_64: u16 = 62;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

// Dynamic tags
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTGOT: i64 = 3;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_FINI: i64 = 13;
const DT_SONAME: i64 = 14;
const DT_JMPREL: i64 = 23;
const DT_BIND_NOW: i64 = 24;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_PREINIT_ARRAY: i64 = 32;
const DT_PREINIT_ARRAYSZ: i64 = 33;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;

// x86_64 relocation types
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_IRELATIVE: u32 = 37;

// 16..=23 are the TLS relocation types (DTPMOD64 .. TPOFF32); 36 TLS_DESC.
pub fn is_tls_reloc(t: u32) -> bool {
    (16..=23).contains(&t) || t == 36
}

#[derive(Clone, Copy, Debug)]
pub struct Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct TlsInfo {
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Sym {
    pub name_off: u32,
    pub info: u8,
    pub value: u64,
    pub size: u64,
    pub shndx: u16,
}

impl Sym {
    pub fn is_undef(&self) -> bool {
        self.shndx == 0
    }
    pub fn stype(&self) -> u8 {
        self.info & 0xf
    }
    pub fn bind(&self) -> u8 {
        self.info >> 4
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Rela {
    pub offset: u64,
    pub r_type: u32,
    pub sym: u32,
    pub addend: i64,
}

/// Defined dynamic symbols (name, base-relative value, st_type) captured for
/// dladdr-style symbolication and future dlsym proxying.
#[derive(Clone, Debug)]
pub struct ExportSym {
    pub name: String,
    pub value: u64,
    pub stype: u8,
}

pub struct ElfFile {
    pub path: PathBuf,
    pub file: File,
    pub data: &'static [u8],
    pub entry: u64,
    pub phoff: u64,
    pub phdrs: Vec<Phdr>,
    pub interp: Option<String>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub tls: Option<TlsInfo>,
    /// PT_GNU_STACK p_memsz (requested stack size; 0 = unspecified).
    pub stack_size: u64,
    pub has_gnu_relro: bool,
    pub has_eh_frame: bool,
    pub has_bind_now: bool,
    dynmap: HashMap<i64, u64>,
    /// (tag, value) in file order; DT_NEEDED repeats, so the map cannot hold
    /// everything.
    dyn_entries: Vec<(i64, u64)>,

    pub symtab: u64,
    pub strtab: u64,
    pub syment: u64,
    pub vhash: u64,
    pub gnu_hash: u64,
    pub versym: u64,
    pub verneed: u64,
    pub verneednum: u64,
    pub rela: u64,
    pub relasz: u64,
    pub relaent: u64,
    pub jmprel: u64,
    pub pltrelsz: u64,
    pub init: u64,
    pub fini: u64,
    pub init_array: u64,
    pub init_arraysz: u64,
    pub preinit_array: u64,
    pub preinit_arraysz: u64,
    pub fini_array: u64,
    pub fini_arraysz: u64,
}

fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(off..off + 2)?.try_into().ok()?))
}
fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(off..off + 4)?.try_into().ok()?))
}
fn rd_i64(d: &[u8], off: usize) -> Option<i64> {
    Some(i64::from_le_bytes(d.get(off..off + 8)?.try_into().ok()?))
}
fn rd_u64(d: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(off..off + 8)?.try_into().ok()?))
}

impl ElfFile {
    pub fn open(path: &Path) -> Result<ElfFile, String> {
        let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let len = file
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?
            .len() as usize;
        if len < 64 {
            return Err(format!("{}: file too small for ELF", path.display()));
        }
        // Parse-only mmap of the whole file (kept for process lifetime).
        let mapped = crate::sys::map_file_ro(file.as_raw_fd(), len)?;
        Self::parse(path, file, mapped)
    }

    fn parse(path: &Path, file: File, data: &'static [u8]) -> Result<ElfFile, String> {
        let bad = |m: &str| format!("{}: {m}", path.display());
        if data.get(0..4) != Some(b"\x7fELF") {
            return Err(bad("not an ELF file"));
        }
        if data[4] != 2 || data[5] != 1 {
            return Err(bad("not ELF64 little-endian"));
        }
        let e_type = rd_u16(data, 16).ok_or_else(|| bad("truncated"))?;
        let e_machine = rd_u16(data, 18).ok_or_else(|| bad("truncated"))?;
        if e_type != ET_EXEC {
            return Err(bad(&format!(
                "e_type={e_type:#x} is not ET_EXEC; elldr only supports non-PIE executables \
                 (PIE/ET_DYN images use dynamic TLS relocation models)"
            )));
        }
        if e_machine != EM_X86_64 {
            return Err(bad(&format!("e_machine={e_machine} is not x86_64")));
        }
        let entry = rd_u64(data, 24).ok_or_else(|| bad("truncated"))?;
        let phoff = rd_u64(data, 32).ok_or_else(|| bad("truncated"))?;
        let phentsize = rd_u16(data, 54).ok_or_else(|| bad("truncated"))? as usize;
        let phnum = rd_u16(data, 56).ok_or_else(|| bad("truncated"))? as usize;
        if phentsize != 56 {
            return Err(bad("unexpected e_phentsize"));
        }

        let mut phdrs = Vec::with_capacity(phnum);
        for i in 0..phnum {
            let off = phoff as usize + i * phentsize;
            let p = Phdr {
                p_type: rd_u32(data, off).ok_or_else(|| bad("truncated phdr"))?,
                p_flags: rd_u32(data, off + 4).ok_or_else(|| bad("truncated phdr"))?,
                p_offset: rd_u64(data, off + 8).ok_or_else(|| bad("truncated phdr"))?,
                p_vaddr: rd_u64(data, off + 16).ok_or_else(|| bad("truncated phdr"))?,
                p_filesz: rd_u64(data, off + 32).ok_or_else(|| bad("truncated phdr"))?,
                p_memsz: rd_u64(data, off + 40).ok_or_else(|| bad("truncated phdr"))?,
                p_align: rd_u64(data, off + 48).ok_or_else(|| bad("truncated phdr"))?,
            };
            phdrs.push(p);
        }

        let mut elf = ElfFile {
            path: path.to_path_buf(),
            file,
            data,
            entry,
            phoff,
            phdrs,
            interp: None,
            needed: Vec::new(),
            soname: None,
            tls: None,
            stack_size: 0,
            has_gnu_relro: false,
            has_eh_frame: false,
            has_bind_now: false,
            dynmap: HashMap::new(),
            dyn_entries: Vec::new(),
            symtab: 0,
            strtab: 0,
            syment: 24,
            vhash: 0,
            gnu_hash: 0,
            versym: 0,
            verneed: 0,
            verneednum: 0,
            rela: 0,
            relasz: 0,
            relaent: 24,
            jmprel: 0,
            pltrelsz: 0,
            init: 0,
            fini: 0,
            init_array: 0,
            init_arraysz: 0,
            preinit_array: 0,
            preinit_arraysz: 0,
            fini_array: 0,
            fini_arraysz: 0,
        };

        let phdr_list = elf.phdrs.clone();
        for p in &phdr_list {
            match p.p_type {
                PT_INTERP => {
                    if let Some(s) = elf.cstr_at(p.p_vaddr) {
                        elf.interp = Some(s);
                    }
                }
                PT_TLS => {
                    elf.tls = Some(TlsInfo {
                        vaddr: p.p_vaddr,
                        filesz: p.p_filesz,
                        memsz: p.p_memsz,
                        align: p.p_align.max(1),
                    });
                }
                PT_GNU_STACK => elf.stack_size = p.p_memsz,
                PT_GNU_RELRO => elf.has_gnu_relro = true,
                PT_GNU_EH_FRAME => elf.has_eh_frame = true,
                PT_DYNAMIC => elf.parse_dynamic(p)?,
                _ => {}
            }
        }

        if elf.dynmap.is_empty() {
            return Err(bad("no PT_DYNAMIC table"));
        }
        elf.symtab = elf.dt(DT_SYMTAB);
        elf.strtab = elf.dt(DT_STRTAB);
        elf.syment = if elf.dt(DT_SYMENT) != 0 {
            elf.dt(DT_SYMENT)
        } else {
            24
        };
        elf.vhash = elf.dt(DT_HASH);
        elf.gnu_hash = elf.dt(DT_GNU_HASH);
        elf.versym = elf.dt(DT_VERSYM);
        elf.verneed = elf.dt(DT_VERNEED);
        elf.verneednum = elf.dt(DT_VERNEEDNUM);
        elf.rela = elf.dt(DT_RELA);
        elf.relasz = elf.dt(DT_RELASZ);
        elf.jmprel = elf.dt(DT_JMPREL);
        elf.pltrelsz = elf.dt(DT_PLTRELSZ);
        elf.init = elf.dt(DT_INIT);
        elf.fini = elf.dt(DT_FINI);
        elf.init_array = elf.dt(DT_INIT_ARRAY);
        elf.init_arraysz = elf.dt(DT_INIT_ARRAYSZ);
        elf.preinit_array = elf.dt(DT_PREINIT_ARRAY);
        elf.preinit_arraysz = elf.dt(DT_PREINIT_ARRAYSZ);
        elf.fini_array = elf.dt(DT_FINI_ARRAY);
        elf.fini_arraysz = elf.dt(DT_FINI_ARRAYSZ);
        elf.has_bind_now = elf.dynmap.contains_key(&DT_BIND_NOW)
            || (elf.dt(DT_FLAGS_1) & 0x1) != 0; // DF_1_NOW

        // NEEDED / SONAME (in file order; DT_NEEDED repeats)
        for &(tag, val) in &elf.dyn_entries {
            if tag == DT_NEEDED || tag == DT_SONAME {
                if let Some(s) = elf.cstr_at(elf.strtab + val) {
                    if tag == DT_NEEDED {
                        elf.needed.push(s);
                    } else {
                        elf.soname = Some(s);
                    }
                }
            }
        }

        if elf.symtab == 0 || elf.strtab == 0 {
            return Err(bad("dynamic table lacks symtab/strtab"));
        }
        Ok(elf)
    }

    fn parse_dynamic(&mut self, p: &Phdr) -> Result<(), String> {
        let n = (p.p_filesz / 16) as usize;
        let base = self.va_to_off(p.p_vaddr);
        for i in 0..n {
            let off = match base {
                Some(b) => b + i * 16,
                None => return Err(format!("{}: dynamic table not in a file segment", self.path.display())),
            };
            let tag = rd_i64(self.data, off).ok_or("truncated dynamic")?;
            let val = rd_u64(self.data, off + 8).ok_or("truncated dynamic")?;
            self.dynmap.insert(tag, val);
            self.dyn_entries.push((tag, val));
            if tag == DT_NULL {
                break;
            }
        }
        Ok(())
    }

    pub fn dt(&self, tag: i64) -> u64 {
        self.dynmap.get(&tag).copied().unwrap_or(0)
    }

    /// VA -> file offset through the PT_LOAD table.
    pub fn va_to_off(&self, va: u64) -> Option<usize> {
        for p in &self.phdrs {
            if p.p_type == PT_LOAD && va >= p.p_vaddr && va < p.p_vaddr + p.p_filesz {
                return Some((va - p.p_vaddr + p.p_offset) as usize);
            }
        }
        None
    }

    pub fn bytes(&self, va: u64, len: usize) -> Option<&[u8]> {
        let off = self.va_to_off(va)?;
        self.data.get(off..off + len)
    }

    pub fn cstr(&self, va: u64) -> Option<String> {
        let off = self.va_to_off(va)?;
        let d = &self.data[off..];
        let end = d.iter().take(4096).position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&d[..end]).into_owned())
    }

    fn cstr_at(&self, va: u64) -> Option<String> {
        self.cstr(va)
    }

    pub fn dynsym(&self, i: u32) -> Option<Sym> {
        let off = self.va_to_off(self.symtab + (i as u64) * self.syment)?;
        Some(Sym {
            name_off: rd_u32(self.data, off)?,
            info: *self.data.get(off + 4)?,
            shndx: rd_u16(self.data, off + 6)?,
            value: rd_u64(self.data, off + 8)?,
            size: rd_u64(self.data, off + 16)?,
        })
    }

    pub fn dynstr(&self, off: u32) -> Option<String> {
        self.cstr(self.strtab + off as u64)
    }

    pub fn symbol_name(&self, s: &Sym) -> Option<String> {
        self.dynstr(s.name_off)
    }

    /// Version needed by dynamic symbol `idx`, if it has one (VERSYM+VERNEED).
    pub fn version_of(&self, idx: u32) -> Option<String> {
        if self.versym == 0 {
            return None;
        }
        let v = rd_u16_maybe(self, self.versym + (idx as u64) * 2)?;
        if v < 2 {
            return None; // local/global, unversioned
        }
        let v = v & 0x7fff;
        self.verneed_map().get(&v).cloned()
    }

    fn verneed_map(&self) -> HashMap<u16, String> {
        let mut m = HashMap::new();
        let mut vn = self.verneed;
        let mut guard = 0;
        while vn != 0 && guard < 256 {
            let Some(off) = self.va_to_off(vn) else { break };
            let Some(cnt) = rd_u16(self.data, off + 2) else { break };
            let Some(aux) = rd_u32(self.data, off + 8) else { break };
            let Some(next) = rd_u32(self.data, off + 12) else { break };
            let mut va = vn + aux as u64;
            for _ in 0..cnt {
                let Some(aoff) = self.va_to_off(va) else { break };
                let Some(other) = rd_u16(self.data, aoff + 6) else { break };
                let Some(name) = rd_u32(self.data, aoff + 8) else { break };
                let Some(anext) = rd_u32(self.data, aoff + 12) else { break };
                if let Some(s) = self.cstr(self.strtab + name as u64) {
                    m.insert(other, s);
                }
                if anext == 0 {
                    break;
                }
                va += anext as u64;
            }
            if next == 0 {
                break;
            }
            vn += next as u64;
            guard += 1;
        }
        m
    }

    /// All RELA entries from DT_RELA plus DT_JMPREL.
    pub fn relas(&self) -> Result<Vec<Rela>, String> {
        let mut out = Vec::new();
        self.read_rela_table(self.rela, self.relasz, &mut out)?;
        self.read_rela_table(self.jmprel, self.pltrelsz, &mut out)?;
        Ok(out)
    }

    fn read_rela_table(&self, va: u64, sz: u64, out: &mut Vec<Rela>) -> Result<(), String> {
        if va == 0 || sz == 0 {
            return Ok(());
        }
        let ent = if self.relaent != 0 { self.relaent } else { 24 };
        if ent != 24 || sz % 24 != 0 {
            return Err(format!(
                "{}: unexpected RELA layout (ent={ent}, sz={sz})",
                self.path.display()
            ));
        }
        let base = self
            .va_to_off(va)
            .ok_or_else(|| format!("{}: RELA table outside segments", self.path.display()))?;
        for i in 0..(sz / 24) as usize {
            let off = base + i * 24;
            let r_offset = rd_u64(self.data, off).ok_or("truncated rela")?;
            let r_info = rd_u64(self.data, off + 8).ok_or("truncated rela")?;
            let addend = rd_i64(self.data, off + 16).ok_or("truncated rela")?;
            out.push(Rela {
                offset: r_offset,
                r_type: (r_info & 0xffff_ffff) as u32,
                sym: (r_info >> 32) as u32,
                addend,
            });
        }
        Ok(())
    }

    /// Defined dynamic symbols, for dladdr-style symbolication.
    pub fn exports(&self) -> Vec<ExportSym> {
        let mut out = Vec::new();
        // The dynsym count is implied by the hash tables; walk the GNU hash to
        // find the symbol count, falling back to a bounded scan.
        let max = self
            .gnu_hash_symbol_count()
            .unwrap_or(0)
            .max(self.hash_symbol_count().unwrap_or(0))
            .max(64);
        for i in 1..max {
            let Some(s) = self.dynsym(i) else { break };
            if s.is_undef() || s.value == 0 {
                continue;
            }
            let st = s.stype();
            if st != 1 && st != 2 && st != 10 {
                // FUNC, OBJECT, GNU_IFUNC
                continue;
            }
            if let Some(name) = self.symbol_name(&s) {
                out.push(ExportSym {
                    name,
                    value: s.value,
                    stype: st,
                });
            }
        }
        out
    }

    fn hash_symbol_count(&self) -> Option<u32> {
        if self.vhash == 0 {
            return None;
        }
        let off = self.va_to_off(self.vhash)?;
        rd_u32(self.data, off + 4)
    }

    fn gnu_hash_symbol_count(&self) -> Option<u32> {
        if self.gnu_hash == 0 {
            return None;
        }
        let off = self.va_to_off(self.gnu_hash)?;
        let nbuckets = rd_u32(self.data, off)?;
        let symoffset = rd_u32(self.data, off + 4)?;
        let bloom_size = rd_u32(self.data, off + 8)? as usize;
        if nbuckets == 0 {
            return Some(symoffset);
        }
        // Buckets start after the bloom filter (8 bytes per bloom word).
        let buckets_off = off + 16 + bloom_size * 8;
        let mut max_sym = symoffset;
        for i in 0..nbuckets as usize {
            let b = rd_u32(self.data, buckets_off + i * 4)?;
            if b > max_sym {
                max_sym = b;
            }
        }
        if max_sym == 0 {
            return Some(symoffset);
        }
        // Walk the chain of the last bucket until its END bit.
        let chain_base = buckets_off + nbuckets as usize * 4;
        let mut idx = max_sym;
        loop {
            let w = rd_u32(self.data, chain_base + (idx - symoffset) as usize * 4)?;
            if w & 1 != 0 {
                return Some(idx + 1);
            }
            idx += 1;
            if idx > 4_000_000 {
                return None;
            }
        }
    }
}

fn rd_u16_maybe(e: &ElfFile, va: u64) -> Option<u16> {
    let off = e.va_to_off(va)?;
    rd_u16(e.data, off)
}
