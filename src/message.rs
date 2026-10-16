//! The normalized internal message representation.
//!
//! Every listener produces [`Message`]s regardless of the wire format, and
//! every output consumes them. Parsing is lossy only in one direction: a
//! payload that cannot be parsed still becomes a `Message` whose
//! `parse_status` says so and whose `message` holds the raw payload.

use std::fmt;
use std::net::SocketAddr;

use crate::time::Timestamp;

/// Syslog facility (RFC 5424 table 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Facility(u8);

impl Facility {
    pub const KERN: Facility = Facility(0);
    pub const USER: Facility = Facility(1);
    pub const AUTH: Facility = Facility(4);
    pub const DAEMON: Facility = Facility(3);
    pub const LOCAL0: Facility = Facility(16);
    pub const LOCAL4: Facility = Facility(20);

    const NAMES: [&'static str; 24] = [
        "kern",
        "user",
        "mail",
        "daemon",
        "auth",
        "syslog",
        "lpr",
        "news",
        "uucp",
        "cron",
        "authpriv",
        "ftp",
        "ntp",
        "security",
        "console",
        "solaris-cron",
        "local0",
        "local1",
        "local2",
        "local3",
        "local4",
        "local5",
        "local6",
        "local7",
    ];

    pub fn from_code(code: u8) -> Option<Facility> {
        (code < 24).then_some(Facility(code))
    }

    pub fn code(self) -> u8 {
        self.0
    }

    pub fn name(self) -> &'static str {
        Self::NAMES[usize::from(self.0)]
    }

    pub fn from_name(name: &str) -> Option<Facility> {
        let lower = name.to_ascii_lowercase();
        let alias = match lower.as_str() {
            "audit" => "security",
            "alert" => "console",
            "clock" | "cron2" => "solaris-cron",
            other => other,
        };
        Self::NAMES
            .iter()
            .position(|n| *n == alias)
            .map(|i| Facility(i as u8))
    }
}

impl fmt::Display for Facility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Syslog severity (RFC 5424 table 2). Lower code means more severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Severity(u8);

impl Severity {
    pub const EMERG: Severity = Severity(0);
    pub const ERR: Severity = Severity(3);
    pub const WARNING: Severity = Severity(4);
    pub const NOTICE: Severity = Severity(5);
    pub const INFO: Severity = Severity(6);
    pub const DEBUG: Severity = Severity(7);

    const NAMES: [&'static str; 8] = [
        "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
    ];

    pub fn from_code(code: u8) -> Option<Severity> {
        (code < 8).then_some(Severity(code))
    }

    pub fn code(self) -> u8 {
        self.0
    }

    pub fn name(self) -> &'static str {
        Self::NAMES[usize::from(self.0)]
    }

    pub fn from_name(name: &str) -> Option<Severity> {
        let lower = name.to_ascii_lowercase();
        let alias = match lower.as_str() {
            "panic" | "emergency" => "emerg",
            "critical" => "crit",
            "error" => "err",
            "warn" => "warning",
            "informational" => "info",
            other => other,
        };
        Self::NAMES
            .iter()
            .position(|n| *n == alias)
            .map(|i| Severity(i as u8))
    }

    /// True if `self` is at least as severe as `threshold`.
    pub fn at_least(self, threshold: Severity) -> bool {
        self.0 <= threshold.0
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How the message reached us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

/// Which parser understood the payload, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseStatus {
    Rfc5424,
    Rfc3164,
    /// Nothing usable could be parsed. `message` holds the whole payload,
    /// facility/severity are the RFC 3164 defaults (user.notice) unless a
    /// valid PRI was found.
    Unparsed {
        reason: String,
    },
}

impl ParseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParseStatus::Rfc5424 => "rfc5424",
            ParseStatus::Rfc3164 => "rfc3164",
            ParseStatus::Unparsed { .. } => "unparsed",
        }
    }
}

/// One RFC 5424 SD-ELEMENT. Parameter order and duplicates are preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdElement {
    pub id: String,
    pub params: Vec<(String, String)>,
}

/// A normalized syslog message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Event time from the message header, converted to UTC. Falls back to
    /// `received_at` when the header has no usable timestamp.
    pub timestamp: Timestamp,
    /// When berlog received the message.
    pub received_at: Timestamp,
    pub facility: Facility,
    pub severity: Severity,
    pub hostname: Option<String>,
    pub appname: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    pub structured_data: Vec<SdElement>,
    pub message: String,
    pub source: SocketAddr,
    pub transport: Transport,
    pub parse_status: ParseStatus,
    /// The payload exceeded `max_message_size` and was cut.
    pub truncated: bool,
}
