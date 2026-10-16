//! Per-source token-bucket rate limiting.
//!
//! Each source IP (not IP:port, so a sender cannot reset its bucket by
//! reconnecting) gets a bucket holding up to `burst` tokens that refills at
//! `messages_per_second`. A message costs one token.
//!
//! Memory is bounded: at most [`MAX_SOURCES`] buckets are tracked. When the
//! table is full, buckets that have refilled completely (idle sources) are
//! evicted; if every tracked source is still active, new sources are let
//! through untracked. Rate limiting exists to protect berlog from a noisy
//! producer, and failing open is the right call when the limiter itself is
//! the thing under pressure.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use crate::config::RateLimitConfig;

pub const MAX_SOURCES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Allowed, and the source had `n` messages dropped since it was last
    /// allowed. Lets the caller log one summary instead of one line per drop.
    AllowAfterDrops(u64),
    /// Dropped. `first` is true for the first drop in a run of drops.
    Drop {
        first: bool,
    },
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
    dropped: u64,
}

#[derive(Debug)]
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    max_sources: usize,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self::with_capacity(cfg, MAX_SOURCES)
    }

    pub fn with_capacity(cfg: RateLimitConfig, max_sources: usize) -> Self {
        RateLimiter {
            rate: cfg.messages_per_second,
            burst: cfg.burst,
            max_sources,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip: IpAddr, now: Instant) -> Verdict {
        // A poisoned lock only means another thread panicked mid-update; the
        // map is still structurally valid, so keep going.
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());

        if !buckets.contains_key(&ip) && buckets.len() >= self.max_sources {
            let (rate, burst) = (self.rate, self.burst);
            buckets.retain(|_, b| {
                let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
                b.tokens + elapsed * rate < burst || b.dropped > 0
            });
            if buckets.len() >= self.max_sources {
                return Verdict::Allow;
            }
        }

        let b = buckets.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last: now,
            dropped: 0,
        });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.rate).min(self.burst);
        b.last = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            match std::mem::take(&mut b.dropped) {
                0 => Verdict::Allow,
                n => Verdict::AllowAfterDrops(n),
            }
        } else {
            b.dropped += 1;
            Verdict::Drop {
                first: b.dropped == 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limiter(rate: f64, burst: f64) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            messages_per_second: rate,
            burst,
        })
    }

    #[test]
    fn burst_then_refill() {
        let rl = limiter(10.0, 3.0);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        assert_eq!(rl.check(ip, t0), Verdict::Allow);
        assert_eq!(rl.check(ip, t0), Verdict::Allow);
        assert_eq!(rl.check(ip, t0), Verdict::Allow);
        assert_eq!(rl.check(ip, t0), Verdict::Drop { first: true });
        assert_eq!(rl.check(ip, t0), Verdict::Drop { first: false });
        // 100ms at 10/s refills exactly one token.
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!(rl.check(ip, t1), Verdict::AllowAfterDrops(2));
        assert_eq!(rl.check(ip, t1), Verdict::Drop { first: true });
        // Refill never exceeds burst.
        let t2 = t1 + Duration::from_secs(60);
        assert_eq!(rl.check(ip, t2), Verdict::AllowAfterDrops(1));
        assert_eq!(rl.check(ip, t2), Verdict::Allow);
        assert_eq!(rl.check(ip, t2), Verdict::Allow);
        assert_eq!(rl.check(ip, t2), Verdict::Drop { first: true });
    }

    #[test]
    fn sources_are_independent() {
        let rl = limiter(1.0, 1.0);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        let t = Instant::now();
        assert_eq!(rl.check(a, t), Verdict::Allow);
        assert_eq!(rl.check(a, t), Verdict::Drop { first: true });
        assert_eq!(rl.check(b, t), Verdict::Allow);
    }

    #[test]
    fn table_is_bounded_and_evicts_idle_sources() {
        let rl = RateLimiter::with_capacity(
            RateLimitConfig {
                messages_per_second: 1.0,
                burst: 1.0,
            },
            2,
        );
        let t = Instant::now();
        let ips: Vec<IpAddr> = (1..=3)
            .map(|i| format!("192.0.2.{i}").parse().unwrap())
            .collect();
        rl.check(ips[0], t);
        rl.check(ips[1], t);
        // Table full, nobody idle: the third source is allowed but untracked.
        assert_eq!(rl.check(ips[2], t), Verdict::Allow);
        assert_eq!(rl.check(ips[2], t), Verdict::Allow);
        assert_eq!(rl.buckets.lock().unwrap().len(), 2);
        // After the others refill, they are evicted and the new one is tracked.
        let later = t + Duration::from_secs(5);
        assert_eq!(rl.check(ips[2], later), Verdict::Allow);
        assert_eq!(rl.check(ips[2], later), Verdict::Drop { first: true });
        assert_eq!(rl.buckets.lock().unwrap().len(), 1);
    }
}
