//! Verbose diagnostics on stderr; target stdout stays untouched.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Event counters for the watchdog thread: a live "how far did we get"
/// breadcrumb trail that survives even when the target's UI stops updating.
pub static BOOTS: AtomicUsize = AtomicUsize::new(0);
pub static BOOT_RETS: AtomicUsize = AtomicUsize::new(0);
pub static WAITER_FIRES: AtomicUsize = AtomicUsize::new(0);
pub static WAITER_TAILS: AtomicUsize = AtomicUsize::new(0);
pub static REG_WAITS: AtomicUsize = AtomicUsize::new(0);
pub static GPA_CALLS: AtomicUsize = AtomicUsize::new(0);
pub static GPA_RESOLVED: AtomicUsize = AtomicUsize::new(0);
pub static CON_READS: AtomicUsize = AtomicUsize::new(0);
pub static CON_EVENTS: AtomicUsize = AtomicUsize::new(0);
pub static THREAD_EXITS: AtomicUsize = AtomicUsize::new(0);
pub static HOST_LOADS: AtomicUsize = AtomicUsize::new(0);
pub static TARGET_LOADS: AtomicUsize = AtomicUsize::new(0);
pub static WORK_QUEUED: AtomicUsize = AtomicUsize::new(0);
pub static WORK_FIRES: AtomicUsize = AtomicUsize::new(0);
pub static WORK_RETS: AtomicUsize = AtomicUsize::new(0);

pub fn bump(c: &AtomicUsize) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn snapshot() -> String {
    format!(
        "boots {}/{} waiter {}/{} regwait {} gpa {}/{} conread {}/{} exits {} loads host/target {}/{} work {}/{}/{}",
        BOOTS.load(Ordering::Relaxed),
        BOOT_RETS.load(Ordering::Relaxed),
        WAITER_FIRES.load(Ordering::Relaxed),
        WAITER_TAILS.load(Ordering::Relaxed),
        REG_WAITS.load(Ordering::Relaxed),
        GPA_CALLS.load(Ordering::Relaxed),
        GPA_RESOLVED.load(Ordering::Relaxed),
        CON_READS.load(Ordering::Relaxed),
        CON_EVENTS.load(Ordering::Relaxed),
        THREAD_EXITS.load(Ordering::Relaxed),
        HOST_LOADS.load(Ordering::Relaxed),
        TARGET_LOADS.load(Ordering::Relaxed),
        WORK_QUEUED.load(Ordering::Relaxed),
        WORK_FIRES.load(Ordering::Relaxed),
        WORK_RETS.load(Ordering::Relaxed),
    )
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
