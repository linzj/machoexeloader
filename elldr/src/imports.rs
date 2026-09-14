//! GOT/PLT relocation processing: COPY relocations first (they define the
//! address later GLOB_DAT/JUMP_SLOT writes must use, glibc semantics), then
//! GLOB_DAT / R_X86_64_64 / JUMP_SLOT resolved through the shim table and the
//! host's already-loaded libraries, and finally the IRELATIVE resolvers.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::elf::{
    self, ElfFile, R_X86_64_64, R_X86_64_COPY, R_X86_64_GLOB_DAT, R_X86_64_IRELATIVE,
    R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE,
};
use crate::image::Image;
use crate::shim;
use crate::sys;
use crate::vlog;

#[derive(Default)]
pub struct BindStats {
    pub copy: usize,
    pub glob_dat: usize,
    pub abs64: usize,
    pub jump_slot: usize,
    pub relative: usize,
    pub shim_hits: Vec<String>,
    pub weak_missing: Vec<String>,
    pub irelative: Vec<(u64, u64)>,
}

static CACHE: Mutex<Option<HashMap<(String, Option<String>), Option<usize>>>> = Mutex::new(None);

/// Host lookup with memoization (negative results cached too). Shim table
/// always wins.
fn resolve(name: &str, version: Option<&str>) -> (Option<usize>, bool) {
    if let Some(a) = shim::shim_for(name) {
        return (Some(a), true);
    }
    let key = (name.to_string(), version.map(str::to_string));
    let mut guard = CACHE.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(v) = map.get(&key) {
        return (*v, false);
    }
    let mut v = None;
    if let Some(ver) = version {
        v = sys::dlvsym_default(name, ver);
    }
    if v.is_none() {
        v = sys::dlsym_default(name);
    }
    map.insert(key, v);
    (v, false)
}

fn sym_name(elf: &ElfFile, symidx: u32) -> Result<(String, Option<String>, bool), String> {
    let sym = elf
        .dynsym(symidx)
        .ok_or_else(|| format!("{}: bad dynsym index {symidx}", elf.path.display()))?;
    let name = elf
        .symbol_name(&sym)
        .ok_or_else(|| format!("{}: bad dynsym name for {symidx}", elf.path.display()))?;
    let weak = sym.bind() == 2; // STB_WEAK
    Ok((name, elf.version_of(symidx), weak))
}

fn write_at(img: &Image, va: u64, val: u64) -> Result<(), String> {
    if img.prot_at(va) & sys::PROT_WRITE == 0 {
        return Err(format!(
            "{}: relocation target {va:#x} is not writable",
            img.elf.path.display()
        ));
    }
    unsafe { *(va as *mut u64) = val };
    Ok(())
}

pub fn bind_all(img: &Image) -> Result<BindStats, String> {
    let elf = &img.elf;
    let relas = elf.relas()?;

    if let Some(r) = relas.iter().find(|r| elf::is_tls_reloc(r.r_type)) {
        return Err(format!(
            "{}: TLS relocation type {} present; elldr only supports local-exec TLS \
             (no dynamic TLS relocation models)",
            elf.path.display(),
            r.r_type
        ));
    }
    let unknown: Vec<u32> = {
        let mut v: Vec<u32> = relas
            .iter()
            .map(|r| r.r_type)
            .filter(|t| {
                !matches!(
                    *t,
                    R_X86_64_64
                        | R_X86_64_COPY
                        | R_X86_64_GLOB_DAT
                        | R_X86_64_JUMP_SLOT
                        | R_X86_64_RELATIVE
                        | R_X86_64_IRELATIVE
                )
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    if !unknown.is_empty() {
        return Err(format!(
            "{}: unsupported relocation types {unknown:?}",
            elf.path.display()
        ));
    }

    let mut stats = BindStats::default();
    let mut copies: HashMap<u32, u64> = HashMap::new();

    // Pass 1: COPY. The host symbol's contents are copied into the target
    // image; references to the symbol inside the target must afterwards bind
    // to the local copy's address.
    for r in &relas {
        if r.r_type != R_X86_64_COPY {
            continue;
        }
        let (name, version, _weak) = sym_name(elf, r.sym)?;
        let (host, _) = resolve(&name, version.as_deref());
        let host = host.ok_or_else(|| {
            format!(
                "{}: copy relocation symbol {name} not found in host process",
                elf.path.display()
            )
        })?;
        let sym = elf.dynsym(r.sym).unwrap();
        let size = sym.size as usize;
        if img.prot_at(r.offset) & sys::PROT_WRITE == 0 {
            return Err(format!(
                "{}: copy target {:#x} is not writable",
                elf.path.display(),
                r.offset
            ));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(host as *const u8, r.offset as *mut u8, size);
        }
        vlog!("copy: {name} <- host {host:#x} ({} bytes)", size);
        copies.insert(r.sym, r.offset);
        stats.copy += 1;
    }

    // Passes 2+3: pointer relocations.
    let mut missing: Vec<String> = Vec::new();
    for r in &relas {
        match r.r_type {
            R_X86_64_COPY => {}
            R_X86_64_RELATIVE => {
                // ET_EXEC: the load bias (l_addr) is zero, addends are
                // already absolute.
                write_at(img, r.offset, r.addend as u64)?;
                stats.relative += 1;
            }
            R_X86_64_IRELATIVE => {
                // Resolver address is the absolute addend (l_addr == 0).
                stats.irelative.push((r.offset, r.addend as u64));
            }
            R_X86_64_GLOB_DAT | R_X86_64_64 | R_X86_64_JUMP_SLOT => {
                let val = if let Some(&local) = copies.get(&r.sym) {
                    local as i64
                } else {
                    let (name, version, weak) = sym_name(elf, r.sym)?;
                    let (addr, via_shim) = resolve(&name, version.as_deref());
                    match addr {
                        Some(a) => {
                            if via_shim && !stats.shim_hits.contains(&name) {
                                stats.shim_hits.push(name.clone());
                            }
                            a as i64
                        }
                        None => {
                            if weak {
                                if !stats.weak_missing.contains(&name) {
                                    stats.weak_missing.push(name);
                                }
                                0
                            } else {
                                missing.push(name);
                                0
                            }
                        }
                    }
                };
                write_at(img, r.offset, (val + r.addend) as u64)?;
                match r.r_type {
                    R_X86_64_GLOB_DAT => stats.glob_dat += 1,
                    R_X86_64_64 => stats.abs64 += 1,
                    _ => stats.jump_slot += 1,
                }
            }
            _ => unreachable!(),
        }
    }

    if !missing.is_empty() {
        missing.sort();
        missing.dedup();
        return Err(format!(
            "{}: unresolved symbols: {}",
            elf.path.display(),
            missing.join(", ")
        ));
    }
    Ok(stats)
}

/// Run IRELATIVE resolvers after every other relocation is in place and
/// store the returned implementations (ld.so semantics).
pub fn run_irelative(list: &[(u64, u64)]) {
    for (slot, resolver) in list {
        let f: extern "C" fn() -> usize = unsafe { std::mem::transmute(*resolver) };
        let v = f();
        unsafe { *(*slot as *mut u64) = v as u64 };
        vlog!("ifunc: {slot:#x} -> {v:#x} (resolver {resolver:#x})");
    }
}
