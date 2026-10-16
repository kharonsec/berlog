//! RFC 5424 parser (strict header, tolerant charset).
//!
//! ```text
//! SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]
//! HEADER     = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
//! ```
//!
//! The header is parsed strictly (field lengths per section 6, a valid
//! timestamp, well-formed SD) because a sender that claims `VERSION 1` and
//! gets it wrong is better reported as `unparsed` than silently mangled.
//! Non-UTF-8 bytes are replaced rather than rejected.

use super::Fields;
use crate::message::SdElement;
use crate::time::Timestamp;

const NIL: &[u8] = b"-";

/// True if the bytes after PRI start with `VERSION SP` (1–3 digits, no
/// leading zero), which is what distinguishes RFC 5424 from RFC 3164.
pub(super) fn looks_like(rest: &[u8]) -> bool {
    let n = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    (1..=3).contains(&n) && rest[0] != b'0' && rest.get(n) == Some(&b' ')
}

pub(super) fn parse(rest: &[u8]) -> Result<Fields, String> {
    let mut cur = Cursor { b: rest, pos: 0 };

    let version = cur.token();
    if version != b"1" {
        return Err(format!(
            "unsupported version {}",
            String::from_utf8_lossy(version)
        ));
    }
    cur.space("VERSION")?;

    let ts = cur.token();
    let timestamp = if ts == NIL {
        None
    } else {
        let s = std::str::from_utf8(ts).map_err(|_| "invalid timestamp".to_owned())?;
        Some(Timestamp::parse_rfc3339(s).ok_or_else(|| format!("invalid timestamp {s:?}"))?)
    };
    cur.space("TIMESTAMP")?;

    let hostname = cur.header_field("HOSTNAME", 255)?;
    cur.space("HOSTNAME")?;
    let appname = cur.header_field("APP-NAME", 48)?;
    cur.space("APP-NAME")?;
    let procid = cur.header_field("PROCID", 128)?;
    cur.space("PROCID")?;
    let msgid = cur.header_field("MSGID", 32)?;
    cur.space("MSGID")?;

    let structured_data = parse_sd(&mut cur)?;

    let message = match cur.peek() {
        None => String::new(),
        Some(b' ') => {
            let mut msg = &cur.b[cur.pos + 1..];
            // A UTF-8 BOM marks the MSG as UTF-8; it is not part of the text.
            if let Some(stripped) = msg.strip_prefix(b"\xEF\xBB\xBF") {
                msg = stripped;
            }
            String::from_utf8_lossy(msg).into_owned()
        }
        Some(_) => return Err("expected SP after STRUCTURED-DATA".to_owned()),
    };

    Ok(Fields {
        timestamp,
        hostname,
        appname,
        procid,
        msgid,
        structured_data,
        message,
    })
}

fn parse_sd(cur: &mut Cursor<'_>) -> Result<Vec<SdElement>, String> {
    if cur.peek() == Some(b'-') {
        cur.pos += 1;
        return Ok(Vec::new());
    }
    if cur.peek() != Some(b'[') {
        return Err("expected STRUCTURED-DATA".to_owned());
    }
    let mut elements = Vec::new();
    while cur.peek() == Some(b'[') {
        cur.pos += 1;
        let id = cur.sd_name("SD-ID")?;
        let mut params = Vec::new();
        loop {
            match cur.peek() {
                Some(b']') => {
                    cur.pos += 1;
                    break;
                }
                Some(b' ') => {
                    cur.pos += 1;
                    let name = cur.sd_name("PARAM-NAME")?;
                    if cur.peek() != Some(b'=') {
                        return Err(format!("expected '=' after PARAM-NAME {name:?}"));
                    }
                    cur.pos += 1;
                    let value = cur.param_value()?;
                    params.push((name, value));
                }
                Some(_) => return Err(format!("unexpected byte in SD-ELEMENT {id:?}")),
                None => return Err("unterminated SD-ELEMENT".to_owned()),
            }
        }
        elements.push(SdElement { id, params });
    }
    Ok(elements)
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    /// Bytes up to (not including) the next SP or end of input.
    fn token(&mut self) -> &'a [u8] {
        let start = self.pos;
        while self.pos < self.b.len() && self.b[self.pos] != b' ' {
            self.pos += 1;
        }
        &self.b[start..self.pos]
    }

    fn space(&mut self, after: &str) -> Result<(), String> {
        if self.peek() == Some(b' ') {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected SP after {after}"))
        }
    }

    /// A NILVALUE-able header field of at most `max` printable ASCII bytes.
    fn header_field(&mut self, name: &str, max: usize) -> Result<Option<String>, String> {
        let tok = self.token();
        if tok.is_empty() {
            return Err(format!("empty {name}"));
        }
        if tok == NIL {
            return Ok(None);
        }
        if tok.len() > max {
            return Err(format!("{name} longer than {max} bytes"));
        }
        if !tok.iter().all(|c| (33..=126).contains(c)) {
            return Err(format!("{name} contains non-printable bytes"));
        }
        Ok(Some(String::from_utf8_lossy(tok).into_owned()))
    }

    /// SD-NAME: 1–32 printable ASCII except `=`, SP, `]`, `"`.
    fn sd_name(&mut self, what: &str) -> Result<String, String> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if (33..=126).contains(&c) && !matches!(c, b'=' | b']' | b'"') {
                self.pos += 1;
            } else {
                break;
            }
        }
        let n = self.pos - start;
        if n == 0 {
            return Err(format!("empty {what}"));
        }
        if n > 32 {
            return Err(format!("{what} longer than 32 bytes"));
        }
        Ok(String::from_utf8_lossy(&self.b[start..self.pos]).into_owned())
    }

    /// `"` PARAM-VALUE `"` with `\"`, `\\`, `\]` escapes. A backslash before
    /// any other byte is kept literally (RFC 5424 section 6.3.3).
    fn param_value(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err("expected '\"' to open PARAM-VALUE".to_owned());
        }
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => return Err("unterminated PARAM-VALUE".to_owned()),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(c @ (b'"' | b'\\' | b']')) => {
                            out.push(c);
                            self.pos += 1;
                        }
                        _ => out.push(b'\\'),
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }
}
