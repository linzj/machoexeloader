//! Symbol resolution: exports trie / symtab for our own images, dlopen/dlsym
//! bridging for system libraries, plus ordinal semantics.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::image::{Image, ImageKind};
use crate::loader::Registry;
use crate::sys;
use crate::vlog;

thread_local! {
    static DLSYM_CACHE: RefCell<HashMap<(usize, String), Option<usize>>> =
        RefCell::new(HashMap::new());
}

fn dlsym_cached(handle: *mut std::ffi::c_void, name: &str) -> Option<usize> {
    let key = (handle as usize, name.to_string());
    if let Some(v) = DLSYM_CACHE.with(|c| c.borrow().get(&key).copied()) {
        return v;
    }
    let v = sys::dlsym_name(handle, name);
    DLSYM_CACHE.with(|c| c.borrow_mut().insert(key, v));
    v
}

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

#[derive(Debug, Clone)]
pub enum Export {
    /// vmaddr of the definition.
    Regular(u64),
    /// Absolute value, not an address.
    Absolute(u64),
    /// vmaddr of the TLV descriptor.
    ThreadLocal(u64),
    /// The definition lives in another image: ordinal + its name there.
    Reexport { ordinal: i32, name: String },
}

/// Builds the export table for one of our loaded images.
pub fn build_exports(img: &Image) -> Result<HashMap<String, Export>, String> {
    let m = img.macho();
    if let Some(t) = m.exports_trie {
        if t.size > 0 {
            let data = img.data(t.off, t.size)?;
            let map = parse_trie(data)?;
            vlog!("{}: {} exports (trie)", img.install_name, map.len());
            return Ok(map);
        }
    }
    if let Some(di) = &m.dyld_info {
        if di.export_size > 0 {
            let data = img.data(di.export_off, di.export_size)?;
            let map = parse_trie(data)?;
            if !map.is_empty() {
                vlog!("{}: {} exports (trie)", img.install_name, map.len());
                return Ok(map);
            }
        }
    }
    let map = symtab_exports(img)?;
    vlog!("{}: {} exports (symtab)", img.install_name, map.len());
    Ok(map)
}

fn uleb(data: &[u8], p: &mut usize) -> Result<u64, String> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        let b = *data.get(*p).ok_or("trie: uleb out of bounds")?;
        *p += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 63 {
            return Err("trie: uleb too long".into());
        }
    }
}

fn trie_str(data: &[u8], p: &mut usize) -> Result<String, String> {
    let start = *p;
    while *data.get(*p).ok_or("trie: string out of bounds")? != 0 {
        *p += 1;
    }
    let s = String::from_utf8_lossy(&data[start..*p]).into_owned();
    *p += 1;
    Ok(s)
}

fn parse_trie(data: &[u8]) -> Result<HashMap<String, Export>, String> {
    let mut out = HashMap::new();
    walk_node(data, 0, "", &mut out, 0)?;
    Ok(out)
}

fn walk_node(
    data: &[u8],
    node: usize,
    prefix: &str,
    out: &mut HashMap<String, Export>,
    depth: usize,
) -> Result<(), String> {
    if depth > 512 {
        return Err("trie: too deep".into());
    }
    if node >= data.len() {
        return Err("trie: node out of bounds".into());
    }
    let mut p = node;
    let terminal_size = uleb(data, &mut p)? as usize;
    if terminal_size != 0 {
        let end = p.checked_add(terminal_size).ok_or("trie overflow")?;
        if end > data.len() {
            return Err("trie: terminal out of bounds".into());
        }
        let flags = uleb(data, &mut p)?;
        if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
            let ordinal = uleb(data, &mut p)?;
            let name = trie_str(data, &mut p)?;
            out.insert(
                prefix.to_string(),
                Export::Reexport {
                    ordinal: ordinal as i32,
                    name,
                },
            );
        } else {
            let address = uleb(data, &mut p)?;
            if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
                // With chained fixups all binding is eager; the stub address
                // (the `address` field) is what callers use.
                let _resolver = uleb(data, &mut p)?;
            }
            let e = match flags & EXPORT_SYMBOL_FLAGS_KIND_MASK {
                EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => Export::ThreadLocal(address),
                EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => Export::Absolute(address),
                _ => Export::Regular(address),
            };
            out.insert(prefix.to_string(), e);
        }
        p = end;
    }
    if p >= data.len() {
        return Err("trie: missing children".into());
    }
    let children = data[p];
    p += 1;
    for _ in 0..children {
        let edge = trie_str(data, &mut p)?;
        let child = uleb(data, &mut p)? as usize;
        let mut name = String::with_capacity(prefix.len() + edge.len());
        name.push_str(prefix);
        name.push_str(&edge);
        walk_node(data, child, &name, out, depth + 1)?;
    }
    Ok(())
}

fn symtab_exports(img: &Image) -> Result<HashMap<String, Export>, String> {
    let m = img.macho();
    let Some(st) = &m.symtab else {
        return Ok(HashMap::new());
    };
    if st.nsyms == 0 {
        return Ok(HashMap::new());
    }
    let syms = img.data(st.symoff, st.nsyms * 16)?;
    let strs = img.data(st.stroff, st.strsize)?;
    let mut out = HashMap::new();
    for i in 0..st.nsyms as usize {
        let e = &syms[i * 16..i * 16 + 16];
        let n_strx = u32::from_le_bytes(e[0..4].try_into().unwrap()) as usize;
        let n_type = e[4];
        let n_value = u64::from_le_bytes(e[8..16].try_into().unwrap());
        if n_type & 0x01 == 0 {
            continue; // not external
        }
        let Ok(name) = trie_str_at(strs, n_strx) else {
            continue;
        };
        match n_type & 0x0e {
            0x0e => {
                out.insert(name, Export::Regular(n_value));
            } // N_SECT
            0x02 => {
                out.insert(name, Export::Absolute(n_value));
            } // N_ABS
            _ => {}
        }
    }
    Ok(out)
}

fn trie_str_at(data: &[u8], start: usize) -> Result<String, String> {
    if start >= data.len() {
        return Err("string offset out of bounds".into());
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .ok_or("unterminated string")?;
    Ok(String::from_utf8_lossy(&data[start..start + end]).into_owned())
}

/// Resolves one symbol for a bind in image `from_idx`.
pub fn resolve(reg: &Registry, from_idx: usize, ordinal: i32, name: &str) -> Result<usize, String> {
    if let Some(a) = crate::entry::shim_lookup(name) {
        return Ok(a);
    }
    resolve_inner(reg, from_idx, ordinal, name, 0)
}

fn resolve_inner(
    reg: &Registry,
    from_idx: usize,
    ordinal: i32,
    name: &str,
    depth: usize,
) -> Result<usize, String> {
    if depth > 8 {
        return Err(format!("symbol {name}: reexport chain too deep"));
    }
    match ordinal {
        0 => lookup_with_reexports(reg, from_idx, name, depth).ok_or_else(|| {
            format!(
                "symbol not found: {name} (expected in {})",
                reg.images[from_idx].install_name
            )
        }),
        -1 => lookup_with_reexports(reg, reg.main, name, depth)
            .ok_or_else(|| format!("symbol not found: {name} (expected in main executable)")),
        -2 | -3 => flat_lookup(reg, name, depth),
        n if n > 0 => {
            let dep = reg.images[from_idx]
                .deps
                .get(n as usize - 1)
                .copied()
                .ok_or_else(|| {
                    format!(
                        "symbol {name}: ordinal {n} out of range ({} has {} deps)",
                        reg.images[from_idx].install_name,
                        reg.images[from_idx].deps.len()
                    )
                })?;
            let dep_img = &reg.images[dep];
            match dep_img.kind {
                ImageKind::SystemBridged => host_lookup(dep_img, name).ok_or_else(|| {
                    format!("symbol not found: {name} (expected in {})", dep_img.install_name)
                }),
                _ => lookup_with_reexports(reg, dep, name, depth)
                    .or_else(|| flat_lookup(reg, name, depth + 1).ok())
                    .ok_or_else(|| {
                        format!("symbol not found: {name} (expected in {})", dep_img.install_name)
                    }),
            }
        }
        _ => Err(format!("symbol {name}: invalid ordinal {ordinal}")),
    }
}

/// Looks a symbol up in one image, following the images it re-exports.
fn lookup_with_reexports(reg: &Registry, idx: usize, name: &str, depth: usize) -> Option<usize> {
    if depth > 8 {
        return None;
    }
    if let Some(a) = lookup_export(reg, idx, name, depth) {
        return Some(a);
    }
    let img = &reg.images[idx];
    let m = img.macho.as_ref()?;
    for (i, d) in m.dylibs.iter().enumerate() {
        if !d.reexport {
            continue;
        }
        if let Some(&child) = img.deps.get(i) {
            if let Some(a) = lookup_with_reexports(reg, child, name, depth + 1) {
                return Some(a);
            }
        }
    }
    None
}

fn lookup_export(reg: &Registry, idx: usize, name: &str, depth: usize) -> Option<usize> {
    let img = &reg.images[idx];
    match img.exports.get(name)? {
        Export::Regular(vm) | Export::ThreadLocal(vm) => Some(img.addr_of(*vm)),
        Export::Absolute(v) => Some(*v as usize),
        Export::Reexport { ordinal, name: import } => {
            vlog!(
                "{name} is a reexport in {}: ordinal {ordinal} name {import}",
                img.install_name
            );
            resolve_inner(reg, idx, *ordinal, import, depth + 1).ok()
        }
    }
}

/// Flat namespace: our images in load order, then the host's global namespace.
fn flat_lookup(reg: &Registry, name: &str, depth: usize) -> Result<usize, String> {
    for (i, img) in reg.images.iter().enumerate() {
        if img.kind == ImageKind::SystemBridged {
            continue;
        }
        if let Some(a) = lookup_export(reg, i, name, depth + 1) {
            return Ok(a);
        }
    }
    if let Some(a) = sys::dlsym_name(sys::RTLD_DEFAULT, name) {
        return Ok(a);
    }
    Err(format!("symbol not found: {name} (flat lookup)"))
}

fn host_lookup(dep: &Image, name: &str) -> Option<usize> {
    if dep.dl_handle != 0 {
        if let Some(a) = dlsym_cached(dep.dl_handle as *mut std::ffi::c_void, name) {
            return Some(a);
        }
    }
    // Symbols that only dyld itself provides (e.g. dyld_stub_binder) may not
    // be findable through the handle; try the global namespace.
    dlsym_cached(sys::RTLD_DEFAULT, name)
}
