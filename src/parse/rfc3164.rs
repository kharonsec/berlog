//! RFC 3164 ("BSD syslog") parser.
//!
//! RFC 3164 is descriptive, not prescriptive: it documents what senders were
//! observed to do. This parser therefore never fails. It extracts what it can
//! and leaves the rest in `message`:
//!
//! ```text
//! <PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG
//! ```
//!
//! Notable behaviors:
//! - The timestamp has no year. We pick whichever of last/this/next year puts
//!   the timestamp closest to the receive time, which handles both a
//!   December message received in January and a sender whose clock is
//!   slightly ahead across New Year.
//! - The timestamp has no zone. It is interpreted as UTC.
//! - Many modern senders put an RFC 3339 timestamp in this position; that is
//!   accepted too.
//! - If there is no valid timestamp, no hostname is guessed (section 4.3.3:
//!   the whole remainder is CONTENT), but a leading TAG is still recognized.

use super::Fields;
use crate::time::Timestamp;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub(super) fn parse(rest: &[u8], received_at: Timestamp) -> Fields {
    let text = String::from_utf8_lossy(rest);
    let mut s: &str = &text;
    let mut fields = Fields::default();

    if let Some((ts, after)) = parse_timestamp(s, received_at) {
        fields.timestamp = Some(ts);
        s = after;
        if let Some((host, after)) = split_hostname(s) {
            fields.hostname = Some(host.to_owned());
            s = after;
        }
    }

    if let Some((tag, pid, after)) = split_tag(s) {
        fields.appname = Some(tag.to_owned());
        fields.procid = pid.map(str::to_owned);
        s = after;
    }

    fields.message = s.to_owned();
    fields
}

/// Returns the timestamp and the remainder after the following SP.
fn parse_timestamp(s: &str, received_at: Timestamp) -> Option<(Timestamp, &str)> {
    let (token_end, after) = match s.find(' ') {
        Some(i) => (i, &s[i + 1..]),
        None => (s.len(), ""),
    };
    // Modern senders (rsyslog, systemd) often use RFC 3339 here.
    if let Some(ts) = Timestamp::parse_rfc3339(&s[..token_end]) {
        return Some((ts, after));
    }
    parse_bsd_timestamp(s, received_at)
}

/// `Mmm dd hh:mm:ss`, where `dd` is space-padded (`Feb  5`). Also tolerates
/// an unpadded day (`Feb 5`) and fractional seconds (`10:00:00.123`).
fn parse_bsd_timestamp(s: &str, received_at: Timestamp) -> Option<(Timestamp, &str)> {
    let b = s.as_bytes();
    let month_name = s.get(0..3)?;
    let month = MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(month_name))? as u32
        + 1;
    if b.get(3) != Some(&b' ') {
        return None;
    }
    let mut i = 4;
    if b.get(i) == Some(&b' ') {
        i += 1;
    }
    let day_start = i;
    while i < b.len() && b[i].is_ascii_digit() && i - day_start < 2 {
        i += 1;
    }
    if i == day_start {
        return None;
    }
    let day: u32 = s[day_start..i].parse().ok()?;
    if b.get(i) != Some(&b' ') {
        return None;
    }
    i += 1;

    let time = b.get(i..i + 8)?;
    let num = |a: usize| -> Option<u32> {
        let (x, y) = (time[a], time[a + 1]);
        (x.is_ascii_digit() && y.is_ascii_digit())
            .then(|| u32::from(x - b'0') * 10 + u32::from(y - b'0'))
    };
    if time[2] != b':' || time[5] != b':' {
        return None;
    }
    let (hour, minute, second) = (num(0)?, num(3)?, num(6)?);
    i += 8;

    let mut nanos = 0u32;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() && j - start < 9 {
            nanos = nanos * 10 + u32::from(b[j] - b'0');
            j += 1;
        }
        if j == start {
            return None;
        }
        nanos *= 10u32.pow(9 - (j - start) as u32);
        i = j;
    }

    let after = match b.get(i) {
        None => "",
        Some(b' ') => &s[i + 1..],
        Some(_) => return None,
    };

    let year = received_at.year();
    let ts = (year - 1..=year + 1)
        .filter_map(|y| Timestamp::from_civil(y, month, day, hour, minute, second, nanos))
        .min_by_key(|t| t.abs_diff_secs(&received_at))?;
    Some((ts, after))
}

/// The first token is a HOSTNAME unless it looks like a TAG (`foo:` or
/// `foo[123]`), in which case the sender omitted the hostname.
fn split_hostname(s: &str) -> Option<(&str, &str)> {
    let end = s.find(' ')?;
    let token = &s[..end];
    if token.is_empty() || token.ends_with(':') || token.contains('[') {
        return None;
    }
    Some((token, &s[end + 1..]))
}

/// Recognize `TAG: `, `TAG[PID]: ` or `TAG[PID] ` at the start of `s`.
/// Returns (tag, pid, remainder).
fn split_tag(s: &str) -> Option<(&str, Option<&str>, &str)> {
    let end = s.find([' ', ':', '['])?;
    let tag = &s[..end];
    if tag.is_empty() || tag.len() > 48 {
        return None;
    }
    let mut rest = &s[end..];
    let mut pid = None;
    if let Some(r) = rest.strip_prefix('[') {
        let close = r.find(']')?;
        let p = &r[..close];
        if p.is_empty() || p.len() > 128 || p.contains(' ') {
            return None;
        }
        pid = Some(p);
        rest = &r[close + 1..];
        rest = rest.strip_prefix(':').unwrap_or(rest);
    } else {
        // Without a colon, a bare word followed by a space is just text.
        rest = rest.strip_prefix(':')?;
    }
    Some((tag, pid, rest.strip_prefix(' ').unwrap_or(rest)))
}
