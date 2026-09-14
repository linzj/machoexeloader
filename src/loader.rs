//! Orchestration: parse the main executable, load dependencies recursively,
//! apply fixups, run initializers and hand control to the entry point.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::fixups;
use crate::image::{self, Image, ImageKind};
use crate::macho;
use crate::resolve;
use crate::vlog;

pub struct Registry {
    pub images: Vec<Image>,
    pub by_path: HashMap<PathBuf, usize>,
    pub main: usize,
}

pub fn run_program(
    target: &str,
    argv: Vec<String>,
    load_only: bool,
    extra_rpaths: &[String],
) -> Result<(), String> {
    let reg = load(target, extra_rpaths)?;
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
            ImageKind::MainExec => "main",
            ImageKind::Dylib => "dylib",
            ImageKind::SystemBridged => "host",
        };
        if img.kind == ImageKind::SystemBridged {
            println!("  [{i}] {tag:>4}  {}", img.install_name);
        } else {
            println!(
                "  [{i}] {tag:>4}  {:<44} base {:#014x} slide {:#x}",
                img.install_name,
                img.base(),
                img.slide
            );
        }
    }
}

pub fn load(target: &str, extra_rpaths: &[String]) -> Result<Registry, String> {
    let path = std::fs::canonicalize(target)
        .map_err(|e| format!("cannot resolve {target:?}: {e}"))?;
    let (m, file) = macho::parse_file(&path)?;
    if !m.is_exec() {
        return Err(format!(
            "{}: not an executable (filetype {:#x})",
            path.display(),
            m.filetype
        ));
    }
    if !m.pie() {
        return Err(format!(
            "{}: not position independent (MH_PIE missing); cannot load at an arbitrary slide",
            path.display()
        ));
    }
    if m.code_signature.is_none() {
        return Err(format!(
            "{}: no code signature; run `codesign -f -s - {}` and retry (Apple Silicon refuses to execute unsigned pages)",
            path.display(),
            path.display()
        ));
    }
    if m.entry_off.is_none() {
        return Err(format!(
            "{}: no LC_MAIN entry point{}",
            path.display(),
            if m.unixthread_pc.is_some() {
                " (LC_UNIXTHREAD targets are not supported in v1)"
            } else {
                ""
            }
        ));
    }
    vlog!(
        "{}: {} segments, {} dylibs, {} rpaths",
        path.display(),
        m.segments.len(),
        m.dylibs.len(),
        m.rpaths.len()
    );

    let install_name = path.display().to_string();
    let mut img = image::map_image(m, &file, ImageKind::MainExec, install_name)?;
    img.exports = resolve::build_exports(&img)?;

    let mut reg = Registry {
        images: vec![img],
        by_path: HashMap::new(),
        main: 0,
    };
    reg.by_path.insert(path.clone(), 0);

    load_deps(&mut reg, 0, extra_rpaths)?;

    let mut pending = Vec::new();
    for i in 0..reg.images.len() {
        pending.extend(fixups::apply_fixups(&reg, i)?);
    }
    fixups::apply_pending(&reg, &pending)?;
    crate::tls::initialize(&reg)?;

    for img in reg.images.iter_mut() {
        img.reprotect()?;
        img.init_funcs = image::collect_init_funcs(img);
    }
    Ok(reg)
}

fn load_deps(reg: &mut Registry, idx: usize, extra: &[String]) -> Result<(), String> {
    let dylibs = reg.images[idx].macho().dylibs.clone();
    for d in dylibs {
        let child = if is_system_path(&d.install_name) {
            ensure_bridged(reg, &d.install_name)?
        } else {
            match resolve_dep_path(reg, idx, &d.install_name, extra) {
                Ok(p) => {
                    if let Some(&c) = reg.by_path.get(&p) {
                        c
                    } else {
                        vlog!(
                            "{} needs {} -> {}",
                            reg.images[idx].install_name,
                            d.install_name,
                            p.display()
                        );
                        let (m, file) = macho::parse_file(&p)?;
                        if !m.is_dylib() {
                            return Err(format!(
                                "{}: dependency is not a dylib (filetype {:#x})",
                                p.display(),
                                m.filetype
                            ));
                        }
                        let name = m.install_name_or_path();
                        let mut img = image::map_image(m, &file, ImageKind::Dylib, name)?;
                        img.exports = resolve::build_exports(&img)?;
                        let new_idx = reg.images.len();
                        reg.by_path.insert(p, new_idx);
                        reg.images.push(img);
                        load_deps(reg, new_idx, extra)?;
                        new_idx
                    }
                }
                Err(e) if d.weak => {
                    vlog!(
                        "{}: skipping missing weak dylib {} ({e})",
                        reg.images[idx].install_name,
                        d.install_name
                    );
                    ensure_placeholder(reg, &d.install_name)
                }
                Err(e) => return Err(e),
            }
        };
        reg.images[idx].deps.push(child);
    }
    Ok(())
}

fn ensure_placeholder(reg: &mut Registry, install: &str) -> usize {
    let key = PathBuf::from(install);
    if let Some(&i) = reg.by_path.get(&key) {
        return i;
    }
    let idx = reg.images.len();
    reg.by_path.insert(key, idx);
    reg.images.push(image::new_placeholder(install));
    idx
}

pub fn is_system_path(name: &str) -> bool {
    name.starts_with("/usr/lib/") || name.starts_with("/System/")
}

fn ensure_bridged(reg: &mut Registry, install: &str) -> Result<usize, String> {
    let key = PathBuf::from(install);
    if let Some(&i) = reg.by_path.get(&key) {
        return Ok(i);
    }
    let img = image::new_bridged(install)?;
    let idx = reg.images.len();
    reg.by_path.insert(key, idx);
    reg.images.push(img);
    Ok(idx)
}

fn resolve_dep_path(
    reg: &Registry,
    from_idx: usize,
    name: &str,
    extra: &[String],
) -> Result<PathBuf, String> {
    let dir_of = |i: usize| -> PathBuf {
        reg.images[i]
            .path
            .as_ref()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_default()
    };
    let main_dir = dir_of(reg.main);
    let from_dir = dir_of(from_idx);
    let expand = |rp: &str| -> PathBuf {
        if let Some(rest) = rp.strip_prefix("@loader_path") {
            from_dir.join(rest.trim_start_matches('/'))
        } else if let Some(rest) = rp.strip_prefix("@executable_path") {
            main_dir.join(rest.trim_start_matches('/'))
        } else {
            PathBuf::from(rp)
        }
    };

    let cand = if let Some(rel) = name.strip_prefix("@rpath/") {
        let mut rpaths: Vec<String> = reg.images[reg.main].macho().rpaths.clone();
        if from_idx != reg.main {
            rpaths.extend(reg.images[from_idx].macho().rpaths.clone());
        }
        rpaths.extend(extra.iter().cloned());
        let mut tried = Vec::new();
        let mut seen = HashSet::new();
        let mut found = None;
        for rp in &rpaths {
            if !seen.insert(rp.clone()) {
                continue;
            }
            let p = expand(rp).join(rel);
            tried.push(p.display().to_string());
            if p.exists() {
                found = Some(p);
                break;
            }
        }
        match found {
            Some(p) => p,
            None => {
                return Err(format!(
                    "{}: @rpath/{rel} not found; tried: {}",
                    name,
                    tried.join(", ")
                ));
            }
        }
    } else if let Some(rel) = name.strip_prefix("@loader_path/") {
        from_dir.join(rel)
    } else if let Some(rel) = name.strip_prefix("@executable_path/") {
        main_dir.join(rel)
    } else {
        PathBuf::from(name)
    };

    std::fs::canonicalize(&cand)
        .map_err(|e| format!("dependency {} not found ({}): {e}", name, cand.display()))
}
