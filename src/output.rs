//! Output sinks and record formatting.
//!
//! Two formats:
//!
//! - **jsonl**: one JSON object per line with a stable schema (absent fields
//!   are `null`, never omitted) so SIEM decoders can rely on it.
//! - **text**: `TIMESTAMP HOST FACILITY.SEVERITY TAG: MESSAGE`, close to
//!   traditional syslog files. Control characters (including LF and NUL) are
//!   escaped as `#ooo` octal, as rsyslog does, so a hostile message cannot
//!   forge extra lines in the file.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Stdout, Write};
use std::path::{Path, PathBuf};

use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;

use crate::config::{Format, OutputSpec};
use crate::message::{Message, ParseStatus, SdElement};

/// A destination for formatted messages.
pub struct Sink {
    kind: SinkKind,
    format: Format,
    /// Set after a write error so the error is logged once, not per message.
    failing: bool,
    dirty: bool,
}

enum SinkKind {
    File {
        path: PathBuf,
        writer: BufWriter<File>,
    },
    Stdout(BufWriter<Stdout>),
}

impl Sink {
    /// Open the sink. File outputs create missing parent directories and are
    /// opened in append mode.
    pub fn open(spec: &OutputSpec) -> io::Result<Sink> {
        let (kind, format) = match spec {
            OutputSpec::File { path, format } => (
                SinkKind::File {
                    path: path.clone(),
                    writer: BufWriter::with_capacity(64 * 1024, open_append(path)?),
                },
                *format,
            ),
            OutputSpec::Stdout { format } => (
                SinkKind::Stdout(BufWriter::with_capacity(64 * 1024, io::stdout())),
                *format,
            ),
        };
        Ok(Sink {
            kind,
            format,
            failing: false,
            dirty: false,
        })
    }

    pub fn describe(&self) -> String {
        let fmt = match self.format {
            Format::Jsonl => "jsonl",
            Format::Text => "text",
        };
        match &self.kind {
            SinkKind::File { path, .. } => format!("file:{} ({fmt})", path.display()),
            SinkKind::Stdout(_) => format!("stdout ({fmt})"),
        }
    }

    pub fn write(&mut self, msg: &Message, scratch: &mut Vec<u8>) {
        scratch.clear();
        match self.format {
            Format::Jsonl => write_jsonl(msg, scratch),
            Format::Text => write_text(msg, scratch),
        }
        let res = match &mut self.kind {
            SinkKind::File { writer, .. } => writer.write_all(scratch),
            SinkKind::Stdout(w) => w.write_all(scratch),
        };
        self.dirty = true;
        self.note(res, "write");
    }

    pub fn flush(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let res = match &mut self.kind {
            SinkKind::File { writer, .. } => writer.flush(),
            SinkKind::Stdout(w) => w.flush(),
        };
        self.note(res, "flush");
    }

    /// Reopen file outputs (after log rotation). Stdout is unaffected.
    pub fn reopen(&mut self) {
        self.flush();
        if let SinkKind::File { path, writer } = &mut self.kind {
            match open_append(path) {
                Ok(f) => {
                    *writer = BufWriter::with_capacity(64 * 1024, f);
                    crate::info!("reopened {}", path.display());
                }
                Err(e) => crate::error!("cannot reopen {}: {e}", path.display()),
            }
        }
    }

    fn note(&mut self, res: io::Result<()>, op: &str) {
        match res {
            Ok(()) if self.failing => {
                self.failing = false;
                crate::info!("{} recovered", self.describe());
            }
            Ok(()) => {}
            Err(e) if !self.failing => {
                self.failing = true;
                crate::error!(
                    "{} failed on {op}: {e} (further errors suppressed until it recovers)",
                    self.describe()
                );
            }
            Err(_) => {}
        }
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o640);
    }
    opts.open(path)
}

// ---------------------------------------------------------------- jsonl

#[derive(Serialize)]
struct JsonRecord<'a> {
    timestamp: String,
    received_at: String,
    facility: &'static str,
    severity: &'static str,
    hostname: Option<&'a str>,
    appname: Option<&'a str>,
    procid: Option<&'a str>,
    msgid: Option<&'a str>,
    structured_data: JsonSd<'a>,
    message: &'a str,
    source: String,
    transport: &'static str,
    parse_status: &'static str,
    parse_error: Option<&'a str>,
    truncated: bool,
}

/// Serializes SD as `{"sd-id": {"param": "value"}}`. RFC 5424 allows a
/// PARAM-NAME to repeat within an element; repeated names become arrays so
/// nothing is lost. (Repeated SD-IDs are forbidden by the RFC; if a sender
/// does it anyway, their params are merged.)
struct JsonSd<'a>(&'a [SdElement]);

impl Serialize for JsonSd<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut ids: Vec<&str> = Vec::new();
        for e in self.0 {
            if !ids.contains(&e.id.as_str()) {
                ids.push(&e.id);
            }
        }
        let mut map = s.serialize_map(Some(ids.len()))?;
        for id in ids {
            let params: Vec<&(String, String)> = self
                .0
                .iter()
                .filter(|e| e.id == id)
                .flat_map(|e| e.params.iter())
                .collect();
            map.serialize_entry(id, &JsonParams(&params))?;
        }
        map.end()
    }
}

struct JsonParams<'a>(&'a [&'a (String, String)]);

impl Serialize for JsonParams<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut names: Vec<&str> = Vec::new();
        for (n, _) in self.0 {
            if !names.contains(&n.as_str()) {
                names.push(n);
            }
        }
        let mut map = s.serialize_map(Some(names.len()))?;
        for name in names {
            let values: Vec<&str> = self
                .0
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
                .collect();
            if let [single] = values[..] {
                map.serialize_entry(name, single)?;
            } else {
                map.serialize_entry(name, &values)?;
            }
        }
        map.end()
    }
}

pub fn write_jsonl(msg: &Message, out: &mut Vec<u8>) {
    let record = JsonRecord {
        timestamp: msg.timestamp.to_string(),
        received_at: msg.received_at.to_string(),
        facility: msg.facility.name(),
        severity: msg.severity.name(),
        hostname: msg.hostname.as_deref(),
        appname: msg.appname.as_deref(),
        procid: msg.procid.as_deref(),
        msgid: msg.msgid.as_deref(),
        structured_data: JsonSd(&msg.structured_data),
        message: &msg.message,
        source: msg.source.to_string(),
        transport: msg.transport.as_str(),
        parse_status: msg.parse_status.as_str(),
        parse_error: match &msg.parse_status {
            ParseStatus::Unparsed { reason } => Some(reason),
            _ => None,
        },
        truncated: msg.truncated,
    };
    // Serializing plain strings, numbers and maps into a Vec cannot fail.
    if serde_json::to_writer(&mut *out, &record).is_err() {
        out.clear();
        out.extend_from_slice(b"{\"error\":\"serialization failed\"}");
    }
    out.push(b'\n');
}

// ---------------------------------------------------------------- text

pub fn write_text(msg: &Message, out: &mut Vec<u8>) {
    let _ = write!(out, "{} ", msg.timestamp);
    match &msg.hostname {
        Some(h) => escape_into(h, out),
        None => {
            let _ = write!(out, "{}", msg.source.ip());
        }
    }
    let _ = write!(out, " {}.{}", msg.facility, msg.severity);
    if let Some(app) = &msg.appname {
        out.push(b' ');
        escape_into(app, out);
        if let Some(pid) = &msg.procid {
            out.push(b'[');
            escape_into(pid, out);
            out.push(b']');
        }
        out.push(b':');
    }
    out.push(b' ');
    escape_into(&msg.message, out);
    out.push(b'\n');
}

/// Copy `s`, replacing ASCII control characters with `#ooo` octal escapes.
fn escape_into(s: &str, out: &mut Vec<u8>) {
    for &b in s.as_bytes() {
        if b < 0x20 || b == 0x7f {
            let _ = write!(out, "#{b:03o}");
        } else {
            out.push(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Facility, Severity, Transport};
    use crate::time::Timestamp;

    fn sample() -> Message {
        let ts = Timestamp::parse_rfc3339("2026-10-16T12:00:00.5Z").unwrap();
        Message {
            timestamp: ts,
            received_at: ts,
            facility: Facility::AUTH,
            severity: Severity::WARNING,
            hostname: Some("web01".into()),
            appname: Some("sshd".into()),
            procid: Some("42".into()),
            msgid: None,
            structured_data: vec![],
            message: "hello".into(),
            source: "192.0.2.7:5140".parse().unwrap(),
            transport: Transport::Tcp,
            parse_status: ParseStatus::Rfc3164,
            truncated: false,
        }
    }

    fn text(m: &Message) -> String {
        let mut v = Vec::new();
        write_text(m, &mut v);
        String::from_utf8(v).unwrap()
    }

    fn json(m: &Message) -> serde_json::Value {
        let mut v = Vec::new();
        write_jsonl(m, &mut v);
        assert_eq!(v.last(), Some(&b'\n'));
        assert_eq!(v.iter().filter(|&&b| b == b'\n').count(), 1);
        serde_json::from_slice(&v).unwrap()
    }

    #[test]
    fn text_format() {
        assert_eq!(
            text(&sample()),
            "2026-10-16T12:00:00.500000Z web01 auth.warning sshd[42]: hello\n"
        );
        let mut m = sample();
        m.hostname = None;
        m.appname = None;
        assert_eq!(
            text(&m),
            "2026-10-16T12:00:00.500000Z 192.0.2.7 auth.warning hello\n"
        );
    }

    #[test]
    fn text_escapes_control_characters() {
        let mut m = sample();
        m.message = "line1\nFAKE 2026 root: x\0\x1b[31m\x7f".into();
        m.hostname = Some("h\r\nx".into());
        let t = text(&m);
        assert_eq!(t.matches('\n').count(), 1);
        assert!(t.contains("h#015#012x"));
        assert!(t.contains("line1#012FAKE 2026 root: x#000#033[31m#177"));
    }

    #[test]
    fn json_schema_is_stable() {
        let v = json(&sample());
        assert_eq!(v["timestamp"], "2026-10-16T12:00:00.500000Z");
        assert_eq!(v["facility"], "auth");
        assert_eq!(v["severity"], "warning");
        assert_eq!(v["hostname"], "web01");
        assert_eq!(v["msgid"], serde_json::Value::Null);
        assert_eq!(v["structured_data"], serde_json::json!({}));
        assert_eq!(v["source"], "192.0.2.7:5140");
        assert_eq!(v["transport"], "tcp");
        assert_eq!(v["parse_status"], "rfc3164");
        assert_eq!(v["parse_error"], serde_json::Value::Null);
        assert_eq!(v["truncated"], false);
        assert_eq!(v.as_object().unwrap().len(), 15);
    }

    #[test]
    fn json_escapes_newlines_and_nuls() {
        let mut m = sample();
        m.message = "a\nb\0c\"d".into();
        let v = json(&m);
        assert_eq!(v["message"], "a\nb\0c\"d");
    }

    #[test]
    fn json_structured_data_with_repeats() {
        let mut m = sample();
        m.structured_data = vec![
            SdElement {
                id: "a@1".into(),
                params: vec![
                    ("x".into(), "1".into()),
                    ("y".into(), "2".into()),
                    ("x".into(), "3".into()),
                ],
            },
            SdElement {
                id: "b@1".into(),
                params: vec![],
            },
        ];
        let v = json(&m);
        assert_eq!(
            v["structured_data"],
            serde_json::json!({"a@1": {"x": ["1", "3"], "y": "2"}, "b@1": {}})
        );
    }

    #[test]
    fn json_unparsed_has_reason() {
        let mut m = sample();
        m.parse_status = ParseStatus::Unparsed {
            reason: "missing or invalid PRI".into(),
        };
        let v = json(&m);
        assert_eq!(v["parse_status"], "unparsed");
        assert_eq!(v["parse_error"], "missing or invalid PRI");
    }
}
