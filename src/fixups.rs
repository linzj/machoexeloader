//! Fixup application: modern chained fixups and classic LC_DYLD_INFO
//! rebase/bind opcodes. Rebases run per image once it is mapped; binds run
//! after all images are loaded (a bind target may live in a later image).

use crate::image::Image;
use crate::loader::Registry;
use crate::macho::LinkeditData;
use crate::resolve;
use crate::vlog;

const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;

const STRIDE_MASK_64: u64 = 0xfff; // 12-bit `next`, 4-byte units
const STRIDE_MASK_ARM64E: u64 = 0x7ff; // 11-bit `next`, 8-byte units

pub struct PendingBind {
    pub from: usize,
    pub name: String,
    pub ordinal: i32,
    pub addr: usize,
    pub addend: i64,
}

pub struct Import {
    pub ordinal: i32,
    pub weak: bool,
    pub addend: i64,
    pub name: String,
}

struct FixupTables<'a> {
    data: &'a [u8],
    imports_offset: usize,
    symbols_offset: usize,
    imports_count: usize,
    imports_format: u32,
}

impl FixupTables<'_> {
    fn parse(img: &Image, cf: LinkeditData) -> Result<FixupTables<'_>, String> {
        let data = img.data(cf.off, cf.size)?;
        if data.len() < 28 {
            return Err(format!("{}: chained fixups payload too small", img.install_name));
        }
        let imports_count = rd32(data, 16) as usize;
        Ok(FixupTables {
            data,
            imports_offset: rd32(data, 8) as usize,
            symbols_offset: rd32(data, 12) as usize,
            imports_count,
            imports_format: rd32(data, 20),
        })
    }

    fn import(&self, i: usize) -> Result<Import, String> {
        if i >= self.imports_count {
            return Err(format!(
                "chained import index {i} out of range (count {})",
                self.imports_count
            ));
        }
        match self.imports_format {
            1 => {
                let raw = rd32(self.data, self.imports_offset + i * 4) as u64;
                let ordinal = sext8((raw & 0xff) as u8);
                let weak = (raw >> 8) & 1 == 1;
                let name_off = (raw >> 9) as usize;
                Ok(Import {
                    ordinal,
                    weak,
                    addend: 0,
                    name: str_at(self.data, self.symbols_offset + name_off)?,
                })
            }
            2 => {
                let off = self.imports_offset + i * 8;
                let raw = rd32(self.data, off) as u64;
                let ordinal = sext8((raw & 0xff) as u8);
                let weak = (raw >> 8) & 1 == 1;
                let name_off = (raw >> 9) as usize;
                let addend = rd32(self.data, off + 4) as i32 as i64;
                Ok(Import {
                    ordinal,
                    weak,
                    addend,
                    name: str_at(self.data, self.symbols_offset + name_off)?,
                })
            }
            3 => {
                let off = self.imports_offset + i * 16;
                let raw = rd64(self.data, off);
                let ordinal = sext16((raw & 0xffff) as u16);
                let weak = (raw >> 16) & 1 == 1;
                let name_off = ((raw >> 32) & 0xffff_ffff) as usize;
                let addend = rd64(self.data, off + 8) as i64;
                Ok(Import {
                    ordinal,
                    weak,
                    addend,
                    name: str_at(self.data, self.symbols_offset + name_off)?,
                })
            }
            other => Err(format!("unsupported chained imports_format {other}")),
        }
    }
}

// ---------------------------------------------------------------- chained

fn decode_next(fmt: u16, raw: u64) -> Result<(u64, bool), String> {
    match fmt {
        2 | 6 => Ok(((raw >> 51) & STRIDE_MASK_64, (raw >> 63) & 1 == 1)),
        1 | 7 | 9 | 12 | 13 => Ok(((raw >> 51) & STRIDE_MASK_ARM64E, (raw >> 62) & 1 == 1)),
        other => Err(format!("unsupported chained pointer format {other}")),
    }
}

fn stride(fmt: u16) -> usize {
    match fmt {
        2 | 6 => 4,
        _ => 8,
    }
}

fn chained_rebase_value(img: &Image, fmt: u16, raw: u64) -> Result<u64, String> {
    match fmt {
        // DYLD_CHAINED_PTR_64_OFFSET: target is a vm offset from the image base
        6 => {
            let target = raw & 0x0000_000f_ffff_ffff; // 36 bits
            let high8 = (raw >> 36) & 0xff;
            Ok((high8 << 56) | (img.base() as u64).wrapping_add(target))
        }
        // DYLD_CHAINED_PTR_64: target is a vmaddr
        2 => {
            let target = raw & 0x0000_000f_ffff_ffff;
            let high8 = (raw >> 36) & 0xff;
            Ok((high8 << 56) | (target as i64).wrapping_add(img.slide) as u64)
        }
        // arm64e userland / userland24 (unauth rebases only)
        1 | 9 | 12 => {
            if (raw >> 63) & 1 == 1 {
                return Err(
                    "arm64e authenticated rebase fixups are not supported in v1".to_string(),
                );
            }
            let target = raw & 0x0000_07ff_ffff_ffff; // 43 bits
            let high8 = (raw >> 43) & 0xff;
            let base = if fmt == 1 {
                (target as i64).wrapping_add(img.slide) as u64
            } else {
                (img.base() as u64).wrapping_add(target)
            };
            Ok((high8 << 56) | base)
        }
        other => Err(format!("unsupported chained rebase format {other}")),
    }
}

fn chained_bind_target(fmt: u16, raw: u64) -> Result<(usize, i64), String> {
    match fmt {
        2 | 6 => Ok((
            (raw & 0x00ff_ffff) as usize, // 24-bit import index
            ((raw >> 24) & 0xff) as i64,  // 8-bit addend
        )),
        1 | 7 | 9 => {
            if (raw >> 63) & 1 == 1 {
                return Err("arm64e authenticated bind fixups are not supported".to_string());
            }
            Ok(((raw & 0xffff) as usize, sext19((raw >> 32) & 0x7ffff)))
        }
        12 => {
            if (raw >> 63) & 1 == 1 {
                return Err("arm64e authenticated bind fixups are not supported".to_string());
            }
            Ok(((raw & 0x00ff_ffff) as usize, sext19((raw >> 32) & 0x7ffff)))
        }
        other => Err(format!("unsupported chained bind format {other}")),
    }
}

/// Walks every element of every fixup chain, calling `f(addr, raw, fmt, is_bind)`.
fn for_each_chain_element(
    img: &Image,
    cf: LinkeditData,
    mut f: impl FnMut(usize, u64, u16, bool) -> Result<(), String>,
) -> Result<(), String> {
    let m = img.macho();
    let data = img.data(cf.off, cf.size)?;
    if data.len() < 28 || rd32(data, 0) != 0 {
        return Err(format!("{}: bad chained fixups header", img.install_name));
    }
    let starts_offset = rd32(data, 4) as usize;
    if rd32(data, 24) != 0 {
        return Err(format!(
            "{}: compressed chained symbol pool unsupported",
            img.install_name
        ));
    }
    let seg_count = rd32(data, starts_offset) as usize;
    if seg_count != m.segments.len() {
        return Err(format!(
            "{}: chained starts seg_count {seg_count} != segment count {}",
            img.install_name,
            m.segments.len()
        ));
    }
    for si in 0..seg_count {
        let sio = rd32(data, starts_offset + 4 + si * 4) as usize;
        if sio == 0 {
            continue;
        }
        let so = starts_offset + sio;
        let page_size = rd16(data, so + 4) as usize;
        let fmt = rd16(data, so + 6);
        let seg_vmsize = m.segments[si].vmsize as usize;
        let page_count = rd16(data, so + 20) as usize;
        let page_starts = so + 22;
        let chain_starts = page_starts + page_count * 2;
        let seg_runtime = img.addr_of(m.segments[si].vmaddr);
        for page in 0..page_count {
            let ps = rd16(data, page_starts + page * 2);
            if ps == 0xffff {
                continue;
            }
            let mut starts: Vec<usize> = Vec::new();
            if ps & 0x8000 != 0 {
                let mut i = (ps & 0x7fff) as usize;
                loop {
                    let v = rd16(data, chain_starts + i * 2);
                    starts.push((v & 0x7fff) as usize);
                    if v & 0x8000 != 0 {
                        break;
                    }
                    i += 1;
                }
            } else {
                starts.push(ps as usize);
            }
            for st in starts {
                let mut p = seg_runtime + page * page_size + st;
                loop {
                    if p < seg_runtime || p + 8 > seg_runtime + seg_vmsize {
                        return Err(format!(
                            "{}: fixup chain at {p:#x} outside segment {}",
                            img.install_name, m.segments[si].name
                        ));
                    }
                    let raw = unsafe { *(p as *const u64) };
                    let (next, is_bind) = decode_next(fmt, raw)?;
                    f(p, raw, fmt, is_bind)?;
                    if next == 0 {
                        break;
                    }
                    p += (next as usize) * stride(fmt);
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- classic

struct Stream<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Stream<'a> {
    fn new(d: &'a [u8]) -> Stream<'a> {
        Stream { d, p: 0 }
    }

    fn done(&self) -> bool {
        self.p >= self.d.len()
    }

    fn u8(&mut self) -> Result<u8, String> {
        let b = *self.d.get(self.p).ok_or("opcode stream ended early")?;
        self.p += 1;
        Ok(b)
    }

    fn uleb(&mut self) -> Result<u64, String> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 63 {
                return Err("uleb128 too long".into());
            }
        }
    }

    fn sleb(&mut self) -> Result<i64, String> {
        let mut result = 0i64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            result |= ((b & 0x7f) as i64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && (b & 0x40) != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
            if shift > 63 {
                return Err("sleb128 too long".into());
            }
        }
    }

    fn cstr(&mut self) -> Result<String, String> {
        let start = self.p;
        while *self.d.get(self.p).ok_or("string runs past stream end")? != 0 {
            self.p += 1;
        }
        let s = String::from_utf8_lossy(&self.d[start..self.p]).into_owned();
        self.p += 1;
        Ok(s)
    }
}

fn classic_rebases(reg: &Registry, idx: usize) -> Result<(), String> {
    let img = &reg.images[idx];
    let m = img.macho();
    let di = m.dyld_info.as_ref().expect("classic rebases without dyld_info");
    if di.rebase_size == 0 {
        return Ok(());
    }
    let data = img.data(di.rebase_off, di.rebase_size)?;
    let mut s = Stream::new(data);
    // dyld's interpreter starts with pointer type; the stream normally sets
    // it explicitly anyway.
    let mut rtype = 1u8;
    let mut seg = 0usize;
    let mut off = 0u64;
    let do_rebase = |rtype: u8, seg: usize, off: u64| -> Result<(), String> {
        if rtype != 1 {
            return Err(format!("rebase type {rtype} unsupported on arm64"));
        }
        let seg_s = m
            .segments
            .get(seg)
            .ok_or_else(|| format!("rebase segment {seg} out of range"))?;
        let addr = img.addr_of(seg_s.vmaddr + off);
        unsafe { (addr as *mut u64).write(addr as u64) };
        Ok(())
    };
    while !s.done() {
        let b = s.u8()?;
        let op = b & 0xf0;
        let imm = b & 0x0f;
        match op {
            0x00 => break,
            0x10 => rtype = imm,
            0x20 => {
                seg = imm as usize;
                off = s.uleb()?;
            }
            0x30 => off += s.uleb()?,
            0x40 => off += (imm as u64) * 8,
            0x50 => {
                for _ in 0..imm {
                    do_rebase(rtype, seg, off)?;
                    off += 8;
                }
            }
            0x60 => {
                let n = s.uleb()?;
                for _ in 0..n {
                    do_rebase(rtype, seg, off)?;
                    off += 8;
                }
            }
            0x70 => {
                do_rebase(rtype, seg, off)?;
                off += 8 + s.uleb()?;
            }
            0x80 => {
                let n = s.uleb()?;
                let skip = s.uleb()?;
                for _ in 0..n {
                    do_rebase(rtype, seg, off)?;
                    off += 8 + skip;
                }
            }
            _ => return Err(format!("bad rebase opcode {b:#x}")),
        }
    }
    Ok(())
}

#[derive(PartialEq, Clone, Copy)]
enum BindMode {
    Normal,
    Lazy,
    Weak,
}

fn classic_bind_stream(
    reg: &Registry,
    idx: usize,
    off: u32,
    size: u32,
    mode: BindMode,
) -> Result<Vec<PendingBind>, String> {
    let img = &reg.images[idx];
    let m = img.macho();
    let data = img.data(off, size)?;
    let mut s = Stream::new(data);
    let mut pending = Vec::new();

    let mut ordinal: i32 = 0;
    let mut name = String::new();
    let mut symflags: u8 = 0;
    // Default pointer type: lazy streams omit SET_TYPE_IMM (the linker relies
    // on the default, and so does dyld's interpreter).
    let mut btype: u8 = 1;
    let mut addend: i64 = 0;
    let mut seg = 0usize;
    let mut loc = 0u64;

    let do_bind =
        |ordinal: i32, name: &str, symflags: u8, btype: u8, addend: i64, seg: usize, loc: u64,
         pending: &mut Vec<PendingBind>| -> Result<(), String> {
            if btype != 1 {
                return Err(format!("bind type {btype} unsupported on arm64"));
            }
            let seg_s = m
                .segments
                .get(seg)
                .ok_or_else(|| format!("bind segment {seg} out of range"))?;
            let addr = img.addr_of(seg_s.vmaddr + loc);
            let weak = mode == BindMode::Weak || symflags & BIND_SYMBOL_FLAGS_WEAK_IMPORT != 0;
            vlog!(
                "  bind {name} ({}) -> {addr:#x}",
                if weak { "weak" } else { "strong" }
            );
            if weak {
                pending.push(PendingBind {
                    from: idx,
                    name: name.to_string(),
                    ordinal: if mode == BindMode::Weak { -2 } else { ordinal },
                    addr,
                    addend,
                });
                return Ok(());
            }
            let sym = resolve::resolve(reg, idx, ordinal, name)
                .map_err(|e| format!("{}: {e}", img.install_name))?;
            unsafe { (addr as *mut u64).write((sym as i64).wrapping_add(addend) as u64) };
            Ok(())
        };

    while !s.done() {
        let b = s.u8()?;
        let op = b & 0xf0;
        let imm = b & 0x0f;
        match op {
            0x00 => break, // DONE
            0x10 => ordinal = imm as i32,
            0x20 => ordinal = s.uleb()? as i32,
            0x30 => {
                ordinal = if imm == 0 {
                    0
                } else {
                    (imm | 0xf0) as i8 as i32
                };
            }
            0x40 => {
                symflags = imm;
                name = s.cstr()?;
            }
            0x50 => btype = imm,
            0x60 => addend = s.sleb()?,
            0x70 => {
                seg = imm as usize;
                loc = s.uleb()?;
            }
            0x80 => loc += s.uleb()?,
            0x90 => {
                do_bind(ordinal, &name, symflags, btype, addend, seg, loc, &mut pending)?;
                loc += 8;
            }
            0xa0 => {
                do_bind(ordinal, &name, symflags, btype, addend, seg, loc, &mut pending)?;
                loc += 8 + s.uleb()?;
            }
            0xb0 => {
                do_bind(ordinal, &name, symflags, btype, addend, seg, loc, &mut pending)?;
                loc += 8 + (imm as u64) * 8;
            }
            0xc0 => {
                let n = s.uleb()?;
                let skip = s.uleb()?;
                for _ in 0..n {
                    do_bind(ordinal, &name, symflags, btype, addend, seg, loc, &mut pending)?;
                    loc += 8 + skip;
                }
            }
            0xd0 => return Err("BIND_OPCODE_THREADED (chained fixups via dyld info) unsupported".into()),
            _ => return Err(format!("bad bind opcode {b:#x}")),
        }
    }
    Ok(pending)
}

// ---------------------------------------------------------------- entry points

/// Applies all fixups of one image in a single pass over each chain.
///
/// A chain may mix rebase and bind elements; walking it a second time would
/// re-decode already-patched pointers and derail (their `next` bits are gone
/// once the resolved value is written). Call after all images are loaded so
/// bind targets can be resolved. Weak binds are returned for a deferred pass.
pub fn apply_fixups(reg: &Registry, idx: usize) -> Result<Vec<PendingBind>, String> {
    let img = &reg.images[idx];
    if img.macho.is_none() {
        return Ok(Vec::new());
    }
    let m = img.macho();
    let mut pending = Vec::new();
    if let Some(cf) = m.chained_fixups {
        let tables = FixupTables::parse(img, cf)?;
        let mut rebases = 0usize;
        let mut binds = 0usize;
        for_each_chain_element(img, cf, |addr, raw, fmt, is_bind| {
            if is_bind {
                let (import_idx, ptr_addend) = chained_bind_target(fmt, raw)?;
                let imp = tables.import(import_idx)?;
                let total_addend = ptr_addend + imp.addend;
                if imp.weak {
                    pending.push(PendingBind {
                        from: idx,
                        name: imp.name,
                        ordinal: imp.ordinal,
                        addr,
                        addend: total_addend,
                    });
                    return Ok(());
                }
                let sym = resolve::resolve(reg, idx, imp.ordinal, &imp.name)
                    .map_err(|e| format!("{}: {e}", img.install_name))?;
                unsafe {
                    (addr as *mut u64).write((sym as i64).wrapping_add(total_addend) as u64)
                };
                binds += 1;
            } else {
                let v = chained_rebase_value(img, fmt, raw)?;
                unsafe { (addr as *mut u64).write(v) };
                rebases += 1;
            }
            Ok(())
        })?;
        vlog!(
            "{}: {rebases} rebases, {binds} binds (chained)",
            img.install_name
        );
    } else if let Some(di) = &m.dyld_info {
        classic_rebases(reg, idx)?;
        pending.extend(classic_bind_stream(
            reg,
            idx,
            di.bind_off,
            di.bind_size,
            BindMode::Normal,
        )?);
        pending.extend(classic_bind_stream(
            reg,
            idx,
            di.lazy_bind_off,
            di.lazy_bind_size,
            BindMode::Lazy,
        )?);
        pending.extend(classic_bind_stream(
            reg,
            idx,
            di.weak_bind_off,
            di.weak_bind_size,
            BindMode::Weak,
        )?);
    }
    Ok(pending)
}

pub fn apply_pending(reg: &Registry, pending: &[PendingBind]) -> Result<(), String> {
    for pb in pending {
        let v = match resolve::resolve(reg, pb.from, pb.ordinal, &pb.name) {
            Ok(sym) => (sym as i64).wrapping_add(pb.addend) as u64,
            Err(_) => {
                vlog!("  weak bind {} missing, using 0", pb.name);
                0
            }
        };
        unsafe { (pb.addr as *mut u64).write(v) };
    }
    Ok(())
}

// ---------------------------------------------------------------- helpers

fn rd32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

fn rd16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(d[o..o + 2].try_into().unwrap())
}

fn rd64(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

fn str_at(d: &[u8], o: usize) -> Result<String, String> {
    if o >= d.len() {
        return Err(format!("chained symbol name offset {o:#x} out of bounds"));
    }
    let end = d[o..]
        .iter()
        .position(|&b| b == 0)
        .ok_or("unterminated chained symbol name")?;
    Ok(String::from_utf8_lossy(&d[o..o + end]).into_owned())
}

fn sext8(v: u8) -> i32 {
    v as i8 as i32
}

fn sext16(v: u16) -> i32 {
    // Chained ordinals use -15..240 ranges; 16-bit for ADDEND64.
    (v as i16) as i32
}

fn sext19(v: u64) -> i64 {
    let v = v as i64;
    (v << 45) >> 45
}
