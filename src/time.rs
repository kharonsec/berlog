//! Minimal UTC timestamp handling.
//!
//! berlog only needs three things from a date library: "now", parsing the
//! RFC 3339 subset used by RFC 5424, and converting a calendar date to a Unix
//! timestamp (for RFC 3164). That is a few dozen lines of well-known civil
//! calendar arithmetic (Howard Hinnant's `days_from_civil`), so we avoid a
//! date crate dependency.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// A point in time, UTC, with nanosecond precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    secs: i64,
    nanos: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Timestamp {
                secs: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            // Clock before 1970: clamp rather than panic.
            Err(_) => Timestamp { secs: 0, nanos: 0 },
        }
    }

    pub fn from_unix(secs: i64, nanos: u32) -> Self {
        Timestamp {
            secs,
            nanos: nanos.min(999_999_999),
        }
    }

    pub fn unix_secs(&self) -> i64 {
        self.secs
    }

    pub fn subsec_nanos(&self) -> u32 {
        self.nanos
    }

    /// Calendar year of this timestamp (UTC).
    pub fn year(&self) -> i64 {
        civil_from_days(self.secs.div_euclid(86_400)).0
    }

    /// Build a timestamp from UTC calendar fields. Returns `None` if any field
    /// is out of range (including Feb 30 and friends).
    pub fn from_civil(
        year: i64,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        nanos: u32,
    ) -> Option<Self> {
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        // Accept a leap second (:60) and fold it into the next second.
        if hour > 23 || minute > 59 || second > 60 || nanos > 999_999_999 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        let secs = days
            .checked_mul(86_400)?
            .checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))?;
        Some(Timestamp { secs, nanos })
    }

    /// Parse an RFC 3339 timestamp as constrained by RFC 5424 section 6.2.3:
    /// `YYYY-MM-DDTHH:MM:SS[.frac](Z|+hh:mm|-hh:mm)`.
    ///
    /// Tolerances beyond the RFC: up to 9 fractional digits (RFC 5424 says 6),
    /// lowercase `t`/`z`.
    pub fn parse_rfc3339(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() < 20 {
            return None;
        }
        let year = digits(b, 0, 4)? as i64;
        let month = digits(b, 5, 2)?;
        let day = digits(b, 8, 2)?;
        let hour = digits(b, 11, 2)?;
        let minute = digits(b, 14, 2)?;
        let second = digits(b, 17, 2)?;
        if b[4] != b'-'
            || b[7] != b'-'
            || !matches!(b[10], b'T' | b't')
            || b[13] != b':'
            || b[16] != b':'
        {
            return None;
        }

        let mut i = 19;
        let mut nanos: u32 = 0;
        if b.get(i) == Some(&b'.') {
            i += 1;
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                if i - start >= 9 {
                    return None;
                }
                nanos = nanos * 10 + u32::from(b[i] - b'0');
                i += 1;
            }
            let n = i - start;
            if n == 0 {
                return None;
            }
            nanos *= 10u32.pow(9 - n as u32);
        }

        let offset_secs: i64 = match b.get(i) {
            Some(b'Z' | b'z') if i + 1 == b.len() => 0,
            Some(&sign @ (b'+' | b'-')) if i + 6 == b.len() => {
                let oh = digits(b, i + 1, 2)?;
                let om = digits(b, i + 4, 2)?;
                if b[i + 3] != b':' || oh > 23 || om > 59 {
                    return None;
                }
                let off = i64::from(oh * 3600 + om * 60);
                if sign == b'+' {
                    off
                } else {
                    -off
                }
            }
            _ => return None,
        };

        let local = Timestamp::from_civil(year, month, day, hour, minute, second, nanos)?;
        Some(Timestamp {
            secs: local.secs - offset_secs,
            nanos,
        })
    }

    /// Distance between two timestamps in whole seconds (absolute value).
    pub fn abs_diff_secs(&self, other: &Timestamp) -> u64 {
        self.secs.abs_diff(other.secs)
    }
}

impl fmt::Display for Timestamp {
    /// Formats as RFC 3339 UTC with microsecond precision,
    /// e.g. `2026-10-16T14:32:00.123456Z`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.secs.div_euclid(86_400);
        let sod = self.secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            y,
            m,
            d,
            sod / 3600,
            (sod % 3600) / 60,
            sod % 60,
            self.nanos / 1000
        )
    }
}

/// Parse `n` ASCII digits starting at `at`.
fn digits(b: &[u8], at: usize, n: usize) -> Option<u32> {
    let slice = b.get(at..at + n)?;
    let mut v: u32 = 0;
    for &c in slice {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    Some(v)
}

pub(crate) fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub(crate) fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_round_trip() {
        let t = Timestamp::from_civil(1970, 1, 1, 0, 0, 0, 0).unwrap();
        assert_eq!(t.unix_secs(), 0);
        assert_eq!(t.to_string(), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn civil_round_trip_over_wide_range() {
        // Every day from 1900 to 2200 must round-trip.
        let start = days_from_civil(1900, 1, 1);
        let end = days_from_civil(2200, 12, 31);
        for z in start..=end {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
    }

    #[test]
    fn known_dates() {
        let t = Timestamp::from_civil(2003, 10, 11, 22, 14, 15, 3_000_000).unwrap();
        assert_eq!(t.unix_secs(), 1_065_910_455);
        assert_eq!(t.to_string(), "2003-10-11T22:14:15.003000Z");
        let leap = Timestamp::from_civil(2024, 2, 29, 0, 0, 0, 0).unwrap();
        assert_eq!(leap.to_string(), "2024-02-29T00:00:00.000000Z");
        assert!(Timestamp::from_civil(2023, 2, 29, 0, 0, 0, 0).is_none());
        assert!(Timestamp::from_civil(2023, 13, 1, 0, 0, 0, 0).is_none());
        assert!(Timestamp::from_civil(2023, 4, 31, 0, 0, 0, 0).is_none());
    }

    #[test]
    fn rfc3339_rfc5424_examples() {
        // RFC 5424 section 6.2.3.1 examples.
        let a = Timestamp::parse_rfc3339("1985-04-12T23:20:50.52Z").unwrap();
        assert_eq!(a.to_string(), "1985-04-12T23:20:50.520000Z");
        let b = Timestamp::parse_rfc3339("1985-04-12T19:20:50.52-04:00").unwrap();
        assert_eq!(a, b);
        let c = Timestamp::parse_rfc3339("2003-10-11T22:14:15.003Z").unwrap();
        assert_eq!(c.to_string(), "2003-10-11T22:14:15.003000Z");
        let d = Timestamp::parse_rfc3339("2003-08-24T05:14:15.000003-07:00").unwrap();
        assert_eq!(d.to_string(), "2003-08-24T12:14:15.000003Z");
        assert!(Timestamp::parse_rfc3339("2026-01-01T00:00:00+01:00").is_some());
    }

    #[test]
    fn rfc3339_rejects_invalid() {
        // 9 fractional digits are tolerated (RFC 5424 caps at 6), 10 are not.
        assert!(Timestamp::parse_rfc3339("2003-08-24T05:14:15.000000003-07:00").is_some());
        for bad in [
            "",
            "2003-08-24T05:14:15.0000000003Z", // 10 fractional digits
            "2003-08-24T05:14:15",             // no offset
            "2003-08-24 05:14:15Z",            // space separator
            "2003-08-24T05:14:15.Z",           // empty fraction
            "2003-02-30T05:14:15Z",            // invalid day
            "2003-08-24T25:14:15Z",            // invalid hour
            "2003-08-24T05:14:15+0700",        // offset without colon
            "2003-08-24T05:14:15Zjunk",
            "abcd-08-24T05:14:15Z",
        ] {
            assert!(
                Timestamp::parse_rfc3339(bad).is_none(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn negative_timestamps_format() {
        let t = Timestamp::from_unix(-1, 0);
        assert_eq!(t.to_string(), "1969-12-31T23:59:59.000000Z");
    }
}
