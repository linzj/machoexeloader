//! Verbose diagnostics on stderr; target stdout stays untouched.

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Verbose logging via raw write(2). Target threads have the target's TLS
/// template installed over the loader's main-module TLS block, so std's
/// eprintln!/thread_local machinery must not be touched there; log paths
/// must never use Rust std TLS facilities.
#[macro_export]
macro_rules! vlog {
    ($($arg:tt)*) => {
        if $crate::diag::verbose() {
            $crate::sys::raw_stderr(&format!("elldr: {}\n", format_args!($($arg)*)));
        }
    };
}

/// Unconditional raw-stderr logging for error paths that may run on target
/// threads (same TLS restriction as vlog!).
#[macro_export]
macro_rules! rerr {
    ($($arg:tt)*) => {{
        $crate::sys::raw_stderr(&format!("elldr: {}\n", format_args!($($arg)*)));
    }};
}
