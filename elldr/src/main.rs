//! elldr - a userspace ELF (x86_64) executable loader for Linux.
//!
//! Loads a non-PIE ET_EXEC target without going through execve: parses ELF,
//! maps the segments at their linked addresses, binds GOT/PLT relocations
//! against the host's already-loaded glibc (with a small shim table for
//! startup/identity-sensitive symbols), installs the target's local-exec TLS
//! block into the loader's own main-module TLS area, and jumps to the entry
//! point on a dedicated thread with a kernel-style initial stack.

mod diag;
mod elf;
mod entry;
mod image;
mod imports;
mod loader;
mod shim;
mod sys;
mod tls;

use std::process::ExitCode;

const USAGE: &str = "\
usage: elldr [-v] [-e] <executable> [args...]

  -v      verbose diagnostics on stderr
  -e      load and prepare only; do not execute the target
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("elldr: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let mut verbose = false;
    let mut load_only = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-v" => verbose = true,
            "-e" => load_only = true,
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
    loader::run_program(&target, target_argv, load_only)
}
