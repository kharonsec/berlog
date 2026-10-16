//! berlog's own diagnostics, written to stderr.
//!
//! Deliberately tiny: a global level from `BERLOG_LOG` (error, warn, info,
//! debug; default info) and four macros. Under systemd or Docker, stderr is
//! captured by the supervisor, which is where an operator expects it.

use std::fmt;
use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::time::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Read `BERLOG_LOG`. Returns an error message for unknown values.
pub fn init_from_env() -> Result<(), String> {
    match std::env::var("BERLOG_LOG") {
        Err(_) => Ok(()),
        Ok(v) => {
            let level = match v.to_ascii_lowercase().as_str() {
                "error" => Level::Error,
                "warn" | "warning" => Level::Warn,
                "info" | "" => Level::Info,
                "debug" | "trace" => Level::Debug,
                other => return Err(format!("BERLOG_LOG: unknown level {other:?}")),
            };
            set_level(level);
            Ok(())
        }
    }
}

pub fn enabled(level: Level) -> bool {
    level as u8 <= LEVEL.load(Ordering::Relaxed)
}

pub fn emit(level: Level, args: fmt::Arguments<'_>) {
    let tag = match level {
        Level::Error => "ERROR",
        Level::Warn => "WARN",
        Level::Info => "INFO",
        Level::Debug => "DEBUG",
    };
    // A failed write to stderr has nowhere to be reported; ignore it.
    let _ = writeln!(
        std::io::stderr().lock(),
        "{} berlog[{}]: {tag}: {args}",
        Timestamp::now(),
        std::process::id()
    );
}

#[macro_export]
macro_rules! diag {
    ($lvl:expr, $($arg:tt)*) => {
        if $crate::diag::enabled($lvl) {
            $crate::diag::emit($lvl, format_args!($($arg)*))
        }
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::diag!($crate::diag::Level::Error, $($arg)*) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::diag!($crate::diag::Level::Warn, $($arg)*) };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::diag!($crate::diag::Level::Info, $($arg)*) };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::diag!($crate::diag::Level::Debug, $($arg)*) };
}
