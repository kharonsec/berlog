//! RFC 6587 TCP framing.
//!
//! Two framings exist in the wild:
//!
//! - **Octet counting** (section 3.4.1): `MSG-LEN SP SYSLOG-MSG`, where
//!   `MSG-LEN` is a decimal with no leading zero.
//! - **Non-transparent framing** (section 3.4.2): messages separated by LF.
//!
//! [`Framer`] is a pure state machine fed with whatever chunks `read()`
//! returns, so partial reads at any byte boundary behave identically to a
//! single large read. It does no I/O and is unit-tested in isolation.
//!
//! # Framing detection
//!
//! The framing is detected from the first byte of the first frame on a
//! connection (a digit 1–9 means octet counting) and then locked in. Locking
//! matters: without it, an LF-framed message that happens to begin with
//! `2026 ` would be misread as a 2026-byte frame and swallow its successors.
//! In octet-counting mode, a frame that does not start with a valid
//! `MSG-LEN SP` header falls back to LF framing for that one frame, so a
//! confused sender degrades instead of desynchronizing forever.
//!
//! # Resource bounds
//!
//! - At most `max_frame` bytes of payload are buffered per connection. Longer
//!   frames are delivered cut to `max_frame` with `truncated = true`; the
//!   excess is skipped without buffering, so a huge `MSG-LEN` costs nothing
//!   but the bytes the sender actually transmits.
//! - `MSG-LEN` is capped at 10 digits; an 11th digit means "not a header".
//! - No allocation is sized from attacker-controlled input except
//!   `min(MSG-LEN, max_frame)`.

/// One complete syslog payload extracted from a TCP stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub data: Vec<u8>,
    /// The frame was longer than `max_frame`, or the stream ended mid-frame.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unknown,
    OctetCounting,
    LineDelimited,
}

#[derive(Debug)]
enum State {
    /// Between frames.
    Idle,
    /// Reading the `MSG-LEN` digits of an octet-counted frame.
    Header {
        digits: [u8; MAX_LEN_DIGITS],
        n: usize,
    },
    /// Reading an octet-counted payload.
    Octets {
        remaining: u64,
        buf: Vec<u8>,
        truncated: bool,
    },
    /// Reading an LF-terminated line.
    Line { buf: Vec<u8>, overflow: bool },
}

const MAX_LEN_DIGITS: usize = 10;

#[derive(Debug)]
pub struct Framer {
    max_frame: usize,
    mode: Mode,
    state: State,
}

impl Framer {
    pub fn new(max_frame: usize) -> Self {
        Framer {
            max_frame: max_frame.max(1),
            mode: Mode::Unknown,
            state: State::Idle,
        }
    }

    /// Feed bytes from the stream. `emit` is called once per complete frame.
    pub fn push(&mut self, mut input: &[u8], mut emit: impl FnMut(Frame)) {
        while !input.is_empty() {
            match &mut self.state {
                State::Idle => {
                    let c = input[0];
                    if c == b'\n' || c == b'\r' {
                        // Stray separators between frames (some octet-counting
                        // senders append LF anyway).
                        input = &input[1..];
                    } else if self.mode != Mode::LineDelimited && (b'1'..=b'9').contains(&c) {
                        self.state = State::Header {
                            digits: [0; MAX_LEN_DIGITS],
                            n: 0,
                        };
                    } else {
                        if self.mode == Mode::Unknown {
                            self.mode = Mode::LineDelimited;
                        }
                        self.state = State::Line {
                            buf: Vec::new(),
                            overflow: false,
                        };
                    }
                }

                State::Header { digits, n } => {
                    let c = input[0];
                    if c.is_ascii_digit() && *n < MAX_LEN_DIGITS {
                        digits[*n] = c;
                        *n += 1;
                        input = &input[1..];
                    } else if c == b' ' {
                        // `n >= 1` is guaranteed: we only enter Header on a digit.
                        let len = digits[..*n]
                            .iter()
                            .fold(0u64, |acc, d| acc * 10 + u64::from(d - b'0'));
                        input = &input[1..];
                        self.mode = Mode::OctetCounting;
                        let max = self.max_frame as u64;
                        self.state = State::Octets {
                            remaining: len,
                            buf: Vec::with_capacity(len.min(max) as usize),
                            truncated: len > max,
                        };
                    } else {
                        // Not a header after all: treat what we have as the
                        // start of an LF-delimited line and reprocess `c`.
                        if self.mode == Mode::Unknown {
                            self.mode = Mode::LineDelimited;
                        }
                        let buf = digits[..*n].to_vec();
                        self.state = State::Line {
                            buf,
                            overflow: false,
                        };
                    }
                }

                State::Octets {
                    remaining,
                    buf,
                    truncated,
                } => {
                    let take = (*remaining).min(input.len() as u64) as usize;
                    let room = self.max_frame - buf.len();
                    buf.extend_from_slice(&input[..take.min(room)]);
                    *remaining -= take as u64;
                    input = &input[take..];
                    if *remaining == 0 {
                        emit(Frame {
                            data: std::mem::take(buf),
                            truncated: *truncated,
                        });
                        self.state = State::Idle;
                    }
                }

                State::Line { buf, overflow } => {
                    let (chunk, rest, complete) = match input.iter().position(|&b| b == b'\n') {
                        Some(i) => (&input[..i], &input[i + 1..], true),
                        None => (input, &input[input.len()..], false),
                    };
                    let room = self.max_frame - buf.len();
                    if chunk.len() > room {
                        *overflow = true;
                    }
                    buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
                    input = rest;
                    if complete {
                        let mut data = std::mem::take(buf);
                        if data.last() == Some(&b'\r') {
                            data.pop();
                        }
                        let truncated = *overflow;
                        self.state = State::Idle;
                        if !data.is_empty() || truncated {
                            emit(Frame { data, truncated });
                        }
                    }
                }
            }
        }
    }

    /// Signal end of stream. Returns whatever partial frame was pending, so
    /// a sender that closes without a final LF (or mid-frame) loses nothing.
    pub fn finish(self) -> Option<Frame> {
        match self.state {
            State::Idle => None,
            State::Header { digits, n } => Some(Frame {
                data: digits[..n].to_vec(),
                truncated: true,
            }),
            State::Octets { buf, .. } => (!buf.is_empty()).then_some(Frame {
                data: buf,
                truncated: true,
            }),
            State::Line { mut buf, overflow } => {
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                (!buf.is_empty()).then_some(Frame {
                    data: buf,
                    truncated: overflow,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames_with_splits(
        input: &[u8],
        max: usize,
        split: &dyn Fn(&[u8]) -> Vec<&[u8]>,
    ) -> Vec<Frame> {
        let mut f = Framer::new(max);
        let mut out = Vec::new();
        for chunk in split(input) {
            f.push(chunk, |fr| out.push(fr));
        }
        out.extend(f.finish());
        out
    }

    /// Runs the framer whole, byte-by-byte, and at every 2-way split point,
    /// asserting identical output each time.
    fn frames(input: &[u8], max: usize) -> Vec<Frame> {
        let whole = frames_with_splits(input, max, &|b| vec![b]);
        let bytewise = frames_with_splits(input, max, &|b| b.chunks(1).collect());
        assert_eq!(whole, bytewise, "byte-at-a-time differs");
        for cut in 0..=input.len() {
            let split = frames_with_splits(input, max, &|b| vec![&b[..cut], &b[cut..]]);
            assert_eq!(whole, split, "split at {cut} differs");
        }
        whole
    }

    fn ok(s: &str) -> Frame {
        Frame {
            data: s.as_bytes().to_vec(),
            truncated: false,
        }
    }

    fn cut(s: &str) -> Frame {
        Frame {
            data: s.as_bytes().to_vec(),
            truncated: true,
        }
    }

    #[test]
    fn line_delimited() {
        assert_eq!(
            frames(b"<13>one\n<13>two\r\n\n<13>three\n", 1024),
            vec![ok("<13>one"), ok("<13>two"), ok("<13>three")]
        );
    }

    #[test]
    fn line_delimited_without_final_lf() {
        assert_eq!(
            frames(b"<13>one\n<13>two", 1024),
            vec![ok("<13>one"), ok("<13>two")]
        );
    }

    #[test]
    fn octet_counting() {
        assert_eq!(
            frames(b"7 <13>one9 <13>tw\no\n9 <13>three", 1024),
            vec![ok("<13>one"), ok("<13>tw\no\n"), ok("<13>three")]
        );
    }

    #[test]
    fn octet_counting_with_stray_lf_between_frames() {
        assert_eq!(
            frames(b"7 <13>one\n7 <13>two\r\n", 1024),
            vec![ok("<13>one"), ok("<13>two")]
        );
    }

    #[test]
    fn line_mode_is_locked_so_leading_digits_are_not_lengths() {
        // First frame is LF-delimited, so "2026 ..." is not a 2026-byte frame.
        assert_eq!(
            frames(b"<13>a\n2026 is a year\n<13>b\n", 1024),
            vec![ok("<13>a"), ok("2026 is a year"), ok("<13>b")]
        );
    }

    #[test]
    fn octet_mode_falls_back_per_frame_on_bad_header() {
        assert_eq!(
            frames(b"5 <13>a<13>junk\n5 <13>b", 1024),
            vec![ok("<13>a"), ok("<13>junk"), ok("<13>b")]
        );
        // Digits followed by a non-space.
        assert_eq!(
            frames(b"5 <13>a12x\n5 <13>b", 1024),
            vec![ok("<13>a"), ok("12x"), ok("<13>b")]
        );
    }

    #[test]
    fn leading_zero_is_not_an_octet_count() {
        assert_eq!(frames(b"0 x\n", 1024), vec![ok("0 x")]);
    }

    #[test]
    fn eleven_digit_length_is_not_a_header() {
        assert_eq!(frames(b"12345678901 x\n", 1024), vec![ok("12345678901 x")]);
    }

    #[test]
    fn oversized_octet_frame_is_truncated_and_stream_stays_in_sync() {
        let mut input = b"20 <13>0123456789abcdef".to_vec();
        input.extend_from_slice(b"7 <13>ok!");
        assert_eq!(frames(&input, 8), vec![cut("<13>0123"), ok("<13>ok!")]);
    }

    #[test]
    fn oversized_line_is_truncated_and_stream_stays_in_sync() {
        assert_eq!(
            frames(b"<13>0123456789\n<13>ok\n", 8),
            vec![cut("<13>0123"), ok("<13>ok")]
        );
    }

    #[test]
    fn huge_declared_length_does_not_allocate_it() {
        let mut f = Framer::new(64);
        let mut out = Vec::new();
        f.push(b"9999999999 <13>tiny", |fr| out.push(fr));
        assert!(out.is_empty());
        match &f.state {
            State::Octets {
                buf,
                remaining,
                truncated,
            } => {
                assert!(buf.capacity() <= 64);
                assert_eq!(*remaining, 9_999_999_999 - 8);
                assert!(*truncated);
            }
            other => panic!("unexpected state {other:?}"),
        }
        // Stream ends: the partial frame is delivered, flagged.
        assert_eq!(f.finish(), Some(cut("<13>tiny")));
    }

    #[test]
    fn eof_mid_octet_count() {
        assert_eq!(frames(b"7 <13>one12", 1024), vec![ok("<13>one"), cut("12")]);
    }

    #[test]
    fn eof_mid_octet_frame() {
        assert_eq!(frames(b"10 <13>abc", 1024), vec![cut("<13>abc")]);
    }

    #[test]
    fn eof_right_after_header() {
        assert_eq!(frames(b"10 ", 1024), vec![]);
    }

    #[test]
    fn embedded_nul_and_binary_pass_through() {
        assert_eq!(
            frames(b"7 <13>\0\xff\n", 1024),
            vec![Frame {
                data: b"<13>\0\xff\n".to_vec(),
                truncated: false
            }]
        );
    }

    #[test]
    fn empty_input() {
        assert_eq!(frames(b"", 1024), vec![]);
        assert_eq!(frames(b"\n\n\r\n", 1024), vec![]);
    }

    #[test]
    fn deterministic_garbage_never_panics_and_respects_bounds() {
        // xorshift so the test is reproducible without a rand dependency.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let alphabet = b"0123456789 \n\r<>x";
        for _ in 0..2000 {
            let len = (next() % 200) as usize;
            let input: Vec<u8> = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let mut f = Framer::new(16);
            let mut pos = 0;
            while pos < input.len() {
                let step = 1 + (next() % 8) as usize;
                let end = (pos + step).min(input.len());
                f.push(&input[pos..end], |fr| assert!(fr.data.len() <= 16));
                pos = end;
            }
            if let Some(fr) = f.finish() {
                assert!(fr.data.len() <= 16);
            }
        }
    }
}
