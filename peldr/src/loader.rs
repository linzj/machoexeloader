//! Orchestration: parse the main executable, load dependencies recursively,
//! bind imports, set up TLS, register unwind tables, then hand control to the
//! entry point.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::image::{Image, ImageKind};
use crate::pe::Pe;
use crate::sys;
use crate::vlog;

pub struct Registry {
    pub images: Vec<Image>,
    pub by_path: HashMap<PathBuf, usize>,
    /// lowercase file name -> registry index (self-mapped and bridged alike)
    pub by_name: HashMap<String, usize>,
    pub main: usize,
}

pub fn run_program(
    target: &str,
    argv: Vec<String>,
    load_only: bool,
    force_rebase: bool,
    extra_dirs: &[String],
) -> Result<(), String> {
    let reg = load(target, extra_dirs, force_rebase)?;
    crate::shim::install(&reg, extra_dirs);
    if load_only {
        print_images(&reg);
        return Ok(());
    }
    crate::entry::run_target(&reg, argv)
}

pub fn print_images(reg: &Registry) {
    println!("loaded {} image(s):", reg.images.len());
    for (i, img) in reg.images.iter().enumerate() {
        let tag = match img.kind {
            ImageKind::MainExe => "main",
            ImageKind::SelfDll => "self",
            ImageKind::Bridged => "host",
        };
        if img.kind == ImageKind::Bridged {
            println!("  [{i}] {tag:>4}  {}", img.name);
        } else {
            println!(
                "  [{i}] {tag:>4}  {:<40} base {:#014x} delta {:#x}",
                img.name,
                img.base,
                img.delta
            );
        }
    }
    let img = &reg.images[reg.main];
    let pe = img.pe();
    if let Ok(imports) = pe.imports() {
        let funcs: usize = imports.iter().map(|d| d.funcs.len()).sum();
        println!(
            "main: {} sections, {} import DLL(s)/{} function(s), {} relocs, {} unwind entries",
            img.mapped.len(),
            imports.len(),
            funcs,
            img.reloc_count,
            pe.pdata().map(|(_, n)| n).unwrap_or(0)
        );
    }
    if let Some(t) = &img.tls {
        println!(
            "main: TLS template {:#x} bytes + {:#x} zero-fill, callbacks: {}",
            t.template_size,
            t.zero_fill,
            if t.callbacks_rva.is_some() { "yes" } else { "no" }
        );
    }
    let delayed = pe.delay_imports();
    if !delayed.is_empty() {
        let funcs: usize = delayed.iter().map(|d| d.funcs.len()).sum();
        println!("main: {} delay-load DLL(s)/{} function(s) (resolved lazily)", delayed.len(), funcs);
    }
}

pub fn load(target: &str, extra_dirs: &[String], force_rebase: bool) -> Result<Registry, String> {
    let path = canon(Path::new(target))
        .ok_or_else(|| format!("cannot resolve {target:?}"))?;
    let pe = Pe::parse_file(&path)?;
    if !pe.is_exe() {
        return Err(format!(
            "{}: not an executable (Characteristics {:#x})",
            path.display(),
            pe.characteristics
        ));
    }
    if pe.entry_rva == 0 {
        return Err(format!("{}: no entry point", path.display()));
    }
    vlog!(
        "{}: {} sections, image base {:#x}, size {:#x}, entry {:#x}, dllchar {:#x}",
        path.display(),
        pe.sections.len(),
        pe.image_base,
        pe.size_of_image,
        pe.entry_rva,
        pe.dll_characteristics
    );

    let name = file_name_lower(&path);
    let img = Image::map(pe, ImageKind::MainExe, name.clone(), force_rebase)?;

    let mut reg = Registry {
        images: vec![img],
        by_path: HashMap::new(),
        by_name: HashMap::new(),
        main: 0,
    };
    reg.by_path.insert(path.clone(), 0);
    reg.by_name.insert(name, 0);

    crate::shim::init_reals();
    load_deps(&mut reg, 0, extra_dirs, force_rebase)?;

    let mut bound = 0usize;
    for i in 0..reg.images.len() {
        bound += crate::imports::bind_imports(&reg.images, i)?;
    }
    vlog!("bound {bound} import(s) in {} image(s)", reg.images.len());

    crate::tls::initialize(&reg.images)?;

    for img in reg.images.iter_mut() {
        img.reprotect()?;
    }

    for i in 0..reg.images.len() {
        if reg.images[i].kind == ImageKind::Bridged {
            continue;
        }
        if let Some((addr, count)) = reg.images[i].pdata_addr() {
            crate::sys::rtl_add_function_table(addr, count, reg.images[i].base as u64)
                .map_err(|e| format!("{}: {e}", reg.images[i].name))?;
            vlog!("{}: registered {count} unwind entries", reg.images[i].name);
        }
    }

    Ok(reg)
}

fn load_deps(reg: &mut Registry, idx: usize, extra: &[String], force_rebase: bool) -> Result<(), String> {
    let imports = reg.images[idx].pe().imports()?;
    let mut deps = Vec::with_capacity(imports.len());
    for dll in &imports {
        let child = match find_self_dll(reg, idx, &dll.name, extra) {
            Some(p) => {
                if let Some(&c) = reg.by_path.get(&p) {
                    c
                } else {
                    vlog!(
                        "{} needs {} -> {}",
                        reg.images[idx].name,
                        dll.name,
                        p.display()
                    );
                    let pe = Pe::parse_file(&p)?;
                    if !pe.is_dll() {
                        return Err(format!(
                            "{}: dependency is not a DLL (Characteristics {:#x})",
                            p.display(),
                            pe.characteristics
                        ));
                    }
                    let name = file_name_lower(&p);
                    let img = Image::map(pe, ImageKind::SelfDll, name.clone(), force_rebase)?;
                    let new_idx = reg.images.len();
                    reg.by_path.insert(p, new_idx);
                    reg.by_name.insert(name, new_idx);
                    reg.images.push(img);
                    load_deps(reg, new_idx, extra, force_rebase)?;
                    new_idx
                }
            }
            None => bridge(reg, &dll.name)?,
        };
        deps.push(child);
    }
    reg.images[idx].deps = deps;
    Ok(())
}

/// A DLL found next to the executable (or in -L dirs) is loaded by peldr
/// itself; system DLLs and anything else falls through to the host loader.
/// This mirrors mldr's split: user dylibs are mapped by the loader, system
/// libraries are bridged to the host's copies.
fn find_self_dll(reg: &Registry, from_idx: usize, name: &str, extra: &[String]) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(p) = reg.images[from_idx].path.as_ref().and_then(|p| p.parent()) {
        dirs.push(p.to_path_buf());
    }
    if let Some(p) = reg.images[reg.main].path.as_ref().and_then(|p| p.parent()) {
        dirs.push(p.to_path_buf());
    }
    for d in extra {
        dirs.push(PathBuf::from(d));
    }
    for d in dirs {
        if is_under_windows_dir(&d) {
            continue;
        }
        let cand = d.join(name);
        if cand.is_file() {
            if let Some(p) = canon(&cand) {
                return Some(p);
            }
        }
    }
    None
}

/// Anything under %SystemRoot% counts as a system library: never self-mapped,
/// always bridged to the host (the PE analogue of mldr's is_system_path).
pub(crate) fn is_under_windows_dir(dir: &Path) -> bool {
    let d = normalize_path(dir);
    for sysdir in [sys::windows_dir(), sys::system_dir()].into_iter().flatten() {
        let r = sysdir.to_ascii_lowercase();
        if d == r || d.starts_with(&format!("{r}\\")) {
            return true;
        }
    }
    false
}

/// Lowercase and strip the canonicalize() `\\?\` prefix.
pub(crate) fn normalize_path(p: &Path) -> String {
    let s = p.to_string_lossy().to_ascii_lowercase();
    s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string()
}

/// canonicalize() with the `\\?\` prefix stripped (paths the target sees).
pub(crate) fn canon(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p)
        .ok()
        .map(|c| PathBuf::from(normalize_path(&c)))
}

fn bridge(reg: &mut Registry, name: &str) -> Result<usize, String> {
    let lower = name.to_ascii_lowercase();
    if let Some(&i) = reg.by_name.get(&lower) {
        return Ok(i);
    }
    let h = crate::sys::load_library_a(name)
        .map_err(|e| format!("cannot resolve import DLL {name}: {e}"))?;
    let idx = reg.images.len();
    reg.images.push(Image::new_bridged(lower.clone(), h as usize));
    reg.by_name.insert(lower, idx);
    vlog!("bridged {name} -> host handle {h:p}");
    Ok(idx)
}

pub fn file_name_lower(path: &Path) -> String {
    path.file_name()
        .map(|f| f.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}
