use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Verbose diagnostics go to stderr so target stdout stays clean.
#[macro_export]
macro_rules! vlog {
    ($($arg:tt)*) => {
        if $crate::diag::verbose() {
            eprintln!("mldr: {}", format_args!($($arg)*));
        }
    };
}
