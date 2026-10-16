//! berlog: a minimal syslog daemon.
//!
//! The binary in `main.rs` is a thin wrapper around [`daemon::run`]; the
//! modules are public so integration tests and fuzzers can drive them.

#![forbid(unsafe_code)]

pub mod message;
pub mod parse;
pub mod time;
