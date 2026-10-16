//! Syslog payload parsing.
//!
//! [`parse`] never fails and never panics: every payload becomes a
//! [`Message`]. The dispatch is:
//!
//! 1. No valid `<PRI>` → `Unparsed`, whole payload kept as the message,
//!    facility/severity default to user.notice (RFC 3164 section 4.3.3).
//! 2. `<PRI>` followed by `VERSION SP` → RFC 5424. If the rest of the header
//!    is malformed the message is `Unparsed` but keeps its PRI.
//! 3. Anything else after a valid `<PRI>` → RFC 3164, which is best-effort by
//!    nature and always succeeds.

mod rfc3164;
mod rfc5424;

use std::net::SocketAddr;

use crate::message::{Facility, Message, ParseStatus, SdElement, Severity, Transport};
use crate::time::Timestamp;

/// Facts about a payload that the parser cannot learn from its bytes.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    pub received_at: Timestamp,
    pub source: SocketAddr,
    pub transport: Transport,
    pub truncated: bool,
}

/// Header fields extracted by either parser.
#[derive(Debug, Default)]
pub(crate) struct Fields {
    pub timestamp: Option<Timestamp>,
    pub hostname: Option<String>,
    pub appname: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    pub structured_data: Vec<SdElement>,
    pub message: String,
}

/// Parse one syslog payload (a UDP datagram or one TCP frame).
pub fn parse(payload: &[u8], ctx: Context) -> Message {
    let payload = trim_trailer(payload);

    let unparsed = |pri: Option<(Facility, Severity)>, reason: &str| {
        let (facility, severity) = pri.unwrap_or((Facility::USER, Severity::NOTICE));
        Message {
            timestamp: ctx.received_at,
            received_at: ctx.received_at,
            facility,
            severity,
            hostname: None,
            appname: None,
            procid: None,
            msgid: None,
            structured_data: Vec::new(),
            message: String::from_utf8_lossy(payload).into_owned(),
            source: ctx.source,
            transport: ctx.transport,
            parse_status: ParseStatus::Unparsed {
                reason: reason.to_owned(),
            },
            truncated: ctx.truncated,
        }
    };

    if payload.is_empty() {
        return unparsed(None, "empty payload");
    }
    let Some((facility, severity, rest)) = parse_pri(payload) else {
        return unparsed(None, "missing or invalid PRI");
    };

    let (fields, status) = if rfc5424::looks_like(rest) {
        match rfc5424::parse(rest) {
            Ok(f) => (f, ParseStatus::Rfc5424),
            Err(reason) => {
                return unparsed(Some((facility, severity)), &format!("rfc5424: {reason}"))
            }
        }
    } else {
        (rfc3164::parse(rest, ctx.received_at), ParseStatus::Rfc3164)
    };

    Message {
        timestamp: fields.timestamp.unwrap_or(ctx.received_at),
        received_at: ctx.received_at,
        facility,
        severity,
        hostname: fields.hostname,
        appname: fields.appname,
        procid: fields.procid,
        msgid: fields.msgid,
        structured_data: fields.structured_data,
        message: fields.message,
        source: ctx.source,
        transport: ctx.transport,
        parse_status: status,
        truncated: ctx.truncated,
    }
}

/// Strip trailing LF / CR / NUL that senders commonly append to datagrams.
fn trim_trailer(mut b: &[u8]) -> &[u8] {
    while let [rest @ .., b'\n' | b'\r' | b'\0'] = b {
        b = rest;
    }
    b
}

/// Parse `<PRI>`: 1–3 digits, value 0..=191. Leading zeros are tolerated
/// (RFC 5424 forbids them, but rejecting them would only lose information).
fn parse_pri(b: &[u8]) -> Option<(Facility, Severity, &[u8])> {
    if b.first() != Some(&b'<') {
        return None;
    }
    let mut value: u32 = 0;
    let mut i = 1;
    while i < b.len() && b[i].is_ascii_digit() {
        if i > 3 {
            return None;
        }
        value = value * 10 + u32::from(b[i] - b'0');
        i += 1;
    }
    if i == 1 || b.get(i) != Some(&b'>') || value > 191 {
        return None;
    }
    let facility = Facility::from_code((value / 8) as u8)?;
    let severity = Severity::from_code((value % 8) as u8)?;
    Some((facility, severity, &b[i + 1..]))
}

#[cfg(test)]
mod tests;
