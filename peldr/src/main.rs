//! peldr - a userspace PE (x86_64) executable loader for Windows.
//!
//! Loads a target executable and its DLL dependencies without going through
//! CreateProcess or the ntdll loader: parses PE, maps sections, applies base
//! relocations, binds imports (bridging system DLLs to the host process),
//! sets up module TLS, registers unwind tables, patches the PEB so the target
//! sees itself as the main image, then sets the PC to the entry point on a
//! dedicated thread.

mod diag;
mod entry;
mod image;
mod imports;
mod loader;
mod pe;
mod shim;
mod sys;
mod tls;

use std::process::ExitCode;

const USAGE: &str = "\
usage: peldr [-v] [-e] [-r] [-L dir] <executable> [args...]

  -v      verbose diagnostics on stderr
  -e      load and prepare only; do not execute the target
  -r      force relocation (never load at the linked ImageBase)
  -L dir  extra DLL search directory
";

fn main() -> ExitCode {
    let args = get_args();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("peldr: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Read our own argv straight from the PEB instead of std::env::args():
/// calling kernel32!GetCommandLineW would prime its process-wide cache with
/// the loader's command line, and the target would then never see ours.
fn get_args() -> Vec<String> {
    unsafe {
        let peb = sys::peb();
        let params = *((peb + 0x20) as *const usize);
        let len = *((params + 0x70) as *const u16) as usize;
        let buf = *((params + 0x78) as *const *const u16);
        if buf.is_null() || len == 0 {
            return Vec::new();
        }
        let mut line: Vec<u16> = std::slice::from_raw_parts(buf, len / 2).to_vec();
        line.push(0);
        let Ok(shell32) = sys::load_library_a("shell32.dll") else {
            return Vec::new();
        };
        let Some(f) = sys::get_proc(shell32, "CommandLineToArgvW") else {
            return Vec::new();
        };
        let f: extern "system" fn(*const u16, *mut i32) -> *mut *mut u16 =
            std::mem::transmute(f);
        let mut argc = 0i32;
        let argv = f(line.as_ptr(), &mut argc);
        if argv.is_null() || argc <= 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(argc as usize);
        for i in 0..argc as usize {
            let p = *argv.add(i);
            if p.is_null() {
                continue;
            }
            let mut n = 0usize;
            while *p.add(n) != 0 && n < 32768 {
                n += 1;
            }
            out.push(String::from_utf16_lossy(std::slice::from_raw_parts(p, n)));
        }
        out
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let mut verbose = false;
    let mut load_only = false;
    let mut force_rebase = false;
    let mut extra_dirs = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-v" => verbose = true,
            "-e" => load_only = true,
            "-r" => force_rebase = true,
            "-L" => {
                i += 1;
                extra_dirs.push(args.get(i).ok_or("-L requires a directory")?.clone());
            }
            s if s.starts_with("-L") && s.len() > 2 => extra_dirs.push(s[2..].to_string()),
            "--" => {
                i += 1;
                break;
            }
            s if s.starts_with('-') && s.len() > 1 => {
                return Err(format!("unknown option {s}\n{USAGE}"));
            }
            _ => break,
        }
        i += 1;
    }
    diag::set_verbose(verbose);
    if i >= args.len() {
        return Err(USAGE.trim_end().to_string());
    }
    let target = args[i].clone();
    let target_argv: Vec<String> = args[i..].to_vec();
    loader::run_program(&target, target_argv, load_only, force_rebase, &extra_dirs)
}
