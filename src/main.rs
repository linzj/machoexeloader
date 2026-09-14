//! mldr - a userspace Mach-O executable loader (mini-dyld).
//!
//! Loads a target executable and its dylib dependencies without going through
//! the kernel's exec path or dyld: parses Mach-O, maps segments, applies
//! chained/classic fixups, resolves symbols (bridging system libraries to the
//! host process), then sets the PC to the entry point.

mod diag;
mod entry;
mod fixups;
mod image;
mod loader;
mod macho;
mod resolve;
mod sys;
mod tls;

use std::process::ExitCode;

const USAGE: &str = "\
usage: mldr [-v] [-e] [-L dir] <executable> [args...]

  -v      verbose diagnostics on stderr
  -e      load and fix up only; do not execute the target
  -L dir  extra @rpath search directory
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mldr: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let mut verbose = false;
    let mut load_only = false;
    let mut extra_rpaths = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-v" => verbose = true,
            "-e" => load_only = true,
            "-L" => {
                i += 1;
                extra_rpaths.push(args.get(i).ok_or("-L requires a directory")?.clone());
            }
            s if s.starts_with("-L") && s.len() > 2 => extra_rpaths.push(s[2..].to_string()),
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
    loader::run_program(&target, target_argv, load_only, &extra_rpaths)
}
