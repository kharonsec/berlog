//! Property-style "never panics" tests for the parse pipeline.
//!
//! No external fuzzing crate: a seeded xorshift generator produces random
//! byte strings and structured mutations of valid messages, which are pushed
//! through the framer, both parsers and both output formats. Each run is
//! deterministic; set BERLOG_FUZZ_ITERS to run longer, BERLOG_FUZZ_SEED to
//! explore a different sequence.

use berlog::framing::Framer;
use berlog::message::{ParseStatus, Transport};
use berlog::output::{write_jsonl, write_text};
use berlog::parse::{parse, Context};
use berlog::time::Timestamp;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

const SEEDS: &[&[u8]] = &[
    b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \xEF\xBB\xBF'su root' failed",
    b"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% do-nuts",
    b"<165>1 2003-10-11T22:14:15.003Z h evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\\\"lication\"][examplePriority@32473 class=\"high\"] msg",
    b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick",
    b"<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!",
    b"<0>1990 Oct 22 10:52:01 TZ-6 scapegoat.dmz.example.org sched[0]: That's All Folks!",
    b"<13>2026-10-16T11:59:58.123+02:00 host app[12]: x",
    b"<191>1 - - - - - -",
];

/// Bytes that are structurally meaningful to the parsers.
const INTERESTING: &[u8] = b"<>[]=\"\\ -:0123456789TZ+.\n\r\0\xef\xbb\xbf\xff";

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(6) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            2 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, INTERESTING[rng.below(INTERESTING.len())]);
            }
            3 if !v.is_empty() => {
                let i = rng.below(v.len());
                v.truncate(i);
            }
            4 => {
                let i = rng.below(v.len() + 1);
                let b = rng.next() as u8;
                v.insert(i, b);
            }
            _ => {
                // Duplicate a slice (repeats SD elements, headers, ...).
                if !v.is_empty() {
                    let a = rng.below(v.len());
                    let b = a + rng.below(v.len() - a);
                    let chunk = v[a..b].to_vec();
                    let at = rng.below(v.len() + 1);
                    v.splice(at..at, chunk);
                }
            }
        }
    }
    v
}

fn ctx() -> Context {
    Context {
        received_at: Timestamp::now(),
        source: "127.0.0.1:1".parse().unwrap(),
        transport: Transport::Tcp,
        truncated: false,
    }
}

fn exercise(payload: &[u8]) {
    let m = parse(payload, ctx());
    let mut out = Vec::new();
    write_jsonl(&m, &mut out);
    let v: serde_json::Value =
        serde_json::from_slice(&out).expect("jsonl output must be valid JSON");
    assert!(v.is_object());
    out.clear();
    write_text(&m, &mut out);
    assert_eq!(
        out.iter().filter(|&&b| b == b'\n').count(),
        1,
        "text output must be exactly one line"
    );
    if let ParseStatus::Unparsed { .. } = m.parse_status {
        assert_eq!(m.message, String::from_utf8_lossy(trim(payload)));
    }
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let [rest @ .., b'\n' | b'\r' | b'\0'] = b {
        b = rest;
    }
    b
}

#[test]
fn parser_never_panics_on_random_bytes() {
    let mut rng = Rng(env_or("BERLOG_FUZZ_SEED", 0x0123_4567_89AB_CDEF) | 1);
    for _ in 0..env_or("BERLOG_FUZZ_ITERS", 20_000) {
        let len = rng.below(300);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        exercise(&bytes);
        // Random bytes behind a valid PRI reach deeper into the parsers.
        let mut with_pri = b"<13>".to_vec();
        with_pri.extend_from_slice(&bytes);
        exercise(&with_pri);
        let mut with_v1 = b"<13>1 ".to_vec();
        with_v1.extend_from_slice(&bytes);
        exercise(&with_v1);
    }
}

#[test]
fn parser_never_panics_on_mutated_valid_messages() {
    let mut rng = Rng(env_or("BERLOG_FUZZ_SEED", 0xFEED_FACE_CAFE_BEEF) | 1);
    for _ in 0..env_or("BERLOG_FUZZ_ITERS", 20_000) {
        let seed = SEEDS[rng.below(SEEDS.len())];
        exercise(&mutate(&mut rng, seed));
    }
}

#[test]
fn framer_and_parser_never_panic_on_random_streams() {
    let mut rng = Rng(env_or("BERLOG_FUZZ_SEED", 0xDEAD_BEEF_0BAD_F00D) | 1);
    for _ in 0..env_or("BERLOG_FUZZ_ITERS", 20_000) / 10 {
        let max = 16 + rng.below(512);
        let mut stream = Vec::new();
        for _ in 0..rng.below(20) {
            let seed = SEEDS[rng.below(SEEDS.len())];
            let msg = mutate(&mut rng, seed);
            match rng.below(3) {
                0 => {
                    stream.extend_from_slice(format!("{} ", msg.len()).as_bytes());
                    stream.extend_from_slice(&msg);
                }
                1 => {
                    stream.extend_from_slice(&msg);
                    stream.push(b'\n');
                }
                _ => {
                    // Lie about the length.
                    let lie = rng.below(msg.len() * 2 + 2);
                    stream.extend_from_slice(format!("{lie} ").as_bytes());
                    stream.extend_from_slice(&msg);
                }
            }
        }
        let mut framer = Framer::new(max);
        let mut pos = 0;
        while pos < stream.len() {
            let end = (pos + 1 + rng.below(64)).min(stream.len());
            framer.push(&stream[pos..end], |f| {
                assert!(f.data.len() <= max);
                exercise(&f.data);
            });
            pos = end;
        }
        if let Some(f) = framer.finish() {
            assert!(f.data.len() <= max);
            exercise(&f.data);
        }
    }
}
