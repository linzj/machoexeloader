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
    // MLDR_TARGET mode (used when a target must never be kernel-exec'd, e.g.
    // policy blocks running it natively): the exec path shim reports mldr's
    // own path, so paths a target captures from _NSGetExecutablePath and later
    // re-execs (Claude Code's find/grep wrappers use ARGV0=bfs/ugrep) land
    // back in mldr, which forwards argv unchanged to MLDR_TARGET.
    entry::set_exec_path_override(match std::env::var_os("MLDR_TARGET") {
        Some(_) => std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().into_owned()),
        None => None,
    });
    let looks_like_mldr = std::path::Path::new(args.first().map(String::as_str).unwrap_or(""))
        .file_name()
        .is_some_and(|n| n == "mldr");
    if !looks_like_mldr {
        if let Ok(target) = std::env::var("MLDR_TARGET") {
            if !target.is_empty() {
                return loader::run_program(&target, args.to_vec(), false, &[]);
            }
        }
    }
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
