//! Import binding: resolve every IAT entry of every self-mapped image, either
//! against another self-mapped image's exports (with forwarder chains) or
//! against the host process (LoadLibrary/GetProcAddress bridge, cached).
//! Runtime shims are injected here for the specific imports we must intercept.

use std::collections::HashMap;

use crate::image::{Image, ImageKind};
use crate::pe::{ExportEntry, ImportName};
use crate::shim;
use crate::vlog;

type Cache = HashMap<(usize, String), Option<usize>>;

pub fn bind_imports(images: &[Image], idx: usize) -> Result<usize, String> {
    let img = &images[idx];
    if img.kind == ImageKind::Bridged {
        return Ok(0);
    }
    let pe = img.pe();
    let dlls = pe.imports()?;
    if dlls.len() != img.deps.len() {
        return Err(format!(
            "{}: internal mismatch: {} import DLLs vs {} recorded deps",
            img.name,
            dlls.len(),
            img.deps.len()
        ));
    }
    let mut cache: Cache = HashMap::new();
    let mut bound = 0usize;
    for (k, dll) in dlls.iter().enumerate() {
        let dep = &images[img.deps[k]];
        for (fi, func) in dll.funcs.iter().enumerate() {
            let addr = if let Some(a) = shim::shim_for(&dll.name, func) {
                if let crate::pe::ImportName::Name(n) = func {
                    vlog!("shim: {}!{} -> injected", dll.name, n);
                }
                a
            } else {
                resolve(images, dep, func, &mut cache, 0)?
            };
            let slot = img.base + dll.iat_rva as usize + fi * 8;
            unsafe {
                *(slot as *mut u64) = addr as u64;
            }
            bound += 1;
        }
        vlog!(
            "{}: bound {} import(s) from {}",
            img.name,
            dll.funcs.len(),
            dll.name
        );
    }
    Ok(bound)
}

/// Resolve one imported name/ordinal in `dep` (self-mapped or bridged).
/// Forwarder chains ("KERNEL32.Sleep") recurse across images, depth-capped.
fn resolve(
    images: &[Image],
    dep: &Image,
    func: &ImportName,
    cache: &mut Cache,
    depth: usize,
) -> Result<usize, String> {
    if depth > 8 {
        return Err("forwarder chain too deep (cycle?)".into());
    }
    match dep.kind {
        ImageKind::Bridged => {
            let key = match func {
                ImportName::Name(n) => (dep.host_handle, n.clone()),
                ImportName::Ordinal(o) => (dep.host_handle, format!("#{o}")),
            };
            if let Some(&c) = cache.get(&key) {
                return c.ok_or_else(|| missing(dep, func));
            }
            let r = match func {
                ImportName::Name(n) => crate::sys::get_proc(dep.host_handle as crate::sys::Handle, n),
                ImportName::Ordinal(o) => {
                    crate::sys::get_proc_ordinal(dep.host_handle as crate::sys::Handle, *o)
                }
            };
            cache.insert(key, r);
            r.ok_or_else(|| missing(dep, func))
        }
        _ => {
            let entry = match func {
                ImportName::Name(n) => dep.exports.get(n).cloned(),
                ImportName::Ordinal(o) => dep.exports_ord.get(&(*o as u32)).cloned(),
            };
            let entry = entry.ok_or_else(|| missing(dep, func))?;
            resolve_entry(images, dep, entry, &missing(dep, func), depth)
        }
    }
}

fn resolve_entry(
    images: &[Image],
    dep: &Image,
    entry: ExportEntry,
    orig: &str,
    depth: usize,
) -> Result<usize, String> {
    match entry {
        ExportEntry::Rva(rva) => Ok(dep.addr_of(rva)),
        ExportEntry::Forwarder(fwd) => {
            let (dll, name) = fwd
                .rsplit_once('.')
                .ok_or_else(|| format!("{orig} (bad forwarder {fwd:?})"))?;
            let target = images
                .iter()
                .find(|im| im.name.eq_ignore_ascii_case(dll));
            match target {
                Some(t) => {
                    let e = match t.exports.get(name) {
                        Some(e) => e.clone(),
                        None => t
                            .exports_ord
                            .get(&name.parse::<u32>().unwrap_or(0))
                            .cloned()
                            .ok_or_else(|| format!("{orig} (forwarder {fwd} missing)"))?,
                    };
                    resolve_entry(images, t, e, orig, depth + 1)
                }
                None => {
                    // Not one of ours: bridge to the host DLL.
                    let h = crate::sys::load_library_a(dll)
                        .map_err(|e| format!("{orig} (forwarder {fwd}: {e})"))?;
                    crate::sys::get_proc(h, name)
                        .ok_or_else(|| format!("{orig} (forwarder {fwd} not found in host)"))
                }
            }
        }
    }
}

fn missing(dep: &Image, func: &ImportName) -> String {
    match func {
        ImportName::Name(n) => format!("import {}!{n} not found", dep.name),
        ImportName::Ordinal(o) => format!("import {}!#{o} not found", dep.name),
    }
}
