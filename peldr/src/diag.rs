//! Verbose diagnostics on stderr; target stdout stays untouched.

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Verbose logging via raw WriteFile. Target threads have their Rust TLS
/// re-pointed at the target's block, so std's eprintln!/thread_local
/// machinery would panic there; writer code must never touch it.
#[macro_export]
macro_rules! vlog {
    ($($arg:tt)*) => {
        if $crate::diag::verbose() {
            $crate::sys::raw_stderr(&format!("peldr: {}\n", format_args!($($arg)*)));
        }
    };
}

/// Unconditional raw-stderr logging for error paths that may run on target
/// threads (same TLS restriction as vlog!).
#[macro_export]
macro_rules! rerr {
    ($($arg:tt)*) => {
        $crate::sys::raw_stderr(&format!("peldr: {}\n", format_args!($($arg)*)));
    };
}
