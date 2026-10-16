//! Listener threads, the writer thread, and orchestration.
//!
//! # Threading model
//!
//! Plain `std::thread`s, no async runtime:
//!
//! ```text
//!  UDP thread ──┐  (parse + rate-limit in the listener)
//!               ├─► bounded mpsc channel ──► writer thread (router + sinks)
//!  TCP accept ──┤
//!   └─ one thread per connection (capped by tcp.max_connections)
//! ```
//!
//! Parsing happens on the listener side, so it scales with connections. One
//! writer thread owns every output, so sinks need no locking and per-file
//! ordering is preserved. The writer flushes whenever the channel drains.
//!
//! Backpressure: TCP connection threads block on a full channel, which
//! stalls the TCP stream and pushes back on the sender. The UDP thread never
//! blocks; if the channel is full it drops and counts, since the kernel
//! would drop the datagram anyway.
//!
//! # Shutdown
//!
//! Signal handlers only set an `AtomicBool`. Listeners use short socket
//! timeouts (or non-blocking accept) and poll it. On shutdown the TCP
//! listener accepts whatever is still in its backlog, and every connection
//! reads what the kernel has already buffered (bounded) without waiting for
//! more, then emits any partial frame. Listeners then exit, dropping their
//! channel senders; the writer drains what is queued, flushes, and exits.

use std::io::{ErrorKind, Read};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::framing::{Frame, Framer};
use crate::message::{Message, Transport};
use crate::parse::{parse, Context};
use crate::ratelimit::{RateLimiter, Verdict};
use crate::router::Router;
use crate::time::Timestamp;
use crate::{debug, error, info, warn};

/// How often blocked threads wake up to check for shutdown.
const POLL: Duration = Duration::from_millis(200);
const ACCEPT_POLL: Duration = Duration::from_millis(50);
const TCP_READ_BUF: usize = 16 * 1024;
/// Per connection, how much already-received data is still read at shutdown.
const SHUTDOWN_DRAIN_BYTES: usize = 1024 * 1024;
/// Largest possible UDP payload (IPv4 65507, IPv6 non-jumbo 65527) fits.
const UDP_RECV_BUF: usize = 65_536;

/// Flags set from signal handlers.
#[derive(Clone, Default)]
pub struct Signals {
    pub shutdown: Arc<AtomicBool>,
    pub reopen: Arc<AtomicBool>,
}

/// Counters reported at shutdown.
#[derive(Debug, Default)]
pub struct Stats {
    pub received: AtomicU64,
    pub written: AtomicU64,
    pub dropped_rate_limited: AtomicU64,
    pub dropped_queue_full: AtomicU64,
    pub tcp_rejected: AtomicU64,
}

struct Shared {
    signals: Signals,
    limiter: Option<RateLimiter>,
    max_message_size: usize,
    stats: Arc<Stats>,
}

impl Shared {
    fn shutting_down(&self) -> bool {
        self.signals.shutdown.load(Ordering::Relaxed)
    }

    /// Apply rate limiting. Returns false if the message must be dropped.
    fn admit(&self, src: SocketAddr) -> bool {
        self.stats.received.fetch_add(1, Ordering::Relaxed);
        let Some(limiter) = &self.limiter else {
            return true;
        };
        match limiter.check(src.ip(), Instant::now()) {
            Verdict::Allow => true,
            Verdict::AllowAfterDrops(n) => {
                warn!(
                    "rate limit: {} is below its limit again, {n} messages were dropped",
                    src.ip()
                );
                true
            }
            Verdict::Drop { first } => {
                self.stats
                    .dropped_rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                if first {
                    warn!("rate limit: dropping messages from {}", src.ip());
                }
                false
            }
        }
    }
}

/// Addresses actually bound (useful when the config asks for port 0).
#[derive(Debug, Clone, Copy)]
pub struct Bound {
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
}

/// Run the daemon until `signals.shutdown` is set. Returns an error only for
/// startup failures (outputs cannot be opened, ports cannot be bound).
pub fn run(config: Config, signals: Signals) -> Result<Arc<Stats>, String> {
    run_with(config, signals, |_| {})
}

/// Like [`run`], calling `on_ready` once listeners are bound.
pub fn run_with(
    config: Config,
    signals: Signals,
    on_ready: impl FnOnce(Bound),
) -> Result<Arc<Stats>, String> {
    let max_message_size = config.max_message_size;
    let queue_size = config.queue_size;
    let udp_addr = config.udp;
    let tcp_cfg = config.tcp.clone();
    let limiter = config.rate_limit.map(RateLimiter::new);

    let router = Router::new(config)?;
    for o in router.describe_outputs() {
        info!("output {o}");
    }

    let udp = udp_addr
        .map(|a| UdpSocket::bind(a).map_err(|e| format!("cannot bind udp {a}: {e}")))
        .transpose()?;
    let tcp = tcp_cfg
        .as_ref()
        .map(|t| {
            TcpListener::bind(t.address).map_err(|e| format!("cannot bind tcp {}: {e}", t.address))
        })
        .transpose()?;

    let bound = Bound {
        udp: udp.as_ref().and_then(|s| s.local_addr().ok()),
        tcp: tcp.as_ref().and_then(|s| s.local_addr().ok()),
    };

    let stats = Arc::new(Stats::default());
    let shared = Arc::new(Shared {
        signals: signals.clone(),
        limiter,
        max_message_size,
        stats: stats.clone(),
    });
    let (tx, rx) = mpsc::sync_channel::<Message>(queue_size);

    let writer = spawn("berlog-writer", {
        let signals = signals.clone();
        let stats = stats.clone();
        move || writer_loop(router, rx, signals, stats)
    })?;

    let mut listeners = Vec::new();
    if let Some(sock) = udp {
        info!(
            "listening on udp {}",
            bound.udp.map_or("?".into(), |a| a.to_string())
        );
        let (tx, shared) = (tx.clone(), shared.clone());
        listeners.push(spawn("berlog-udp", move || udp_loop(sock, tx, shared))?);
    }
    if let (Some(listener), Some(cfg)) = (tcp, tcp_cfg) {
        info!(
            "listening on tcp {}",
            bound.tcp.map_or("?".into(), |a| a.to_string())
        );
        let (tx, shared) = (tx.clone(), shared.clone());
        listeners.push(spawn("berlog-tcp", move || {
            tcp_accept_loop(listener, cfg.max_connections, tx, shared)
        })?);
    }
    // Only listeners hold senders now, so the writer sees disconnection
    // exactly when the last listener has exited.
    drop(tx);

    on_ready(bound);
    info!("ready");

    while !signals.shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
    info!("shutting down");

    for h in listeners {
        if h.join().is_err() {
            error!("a listener thread panicked");
        }
    }
    if writer.join().is_err() {
        error!("writer thread panicked");
    }

    info!(
        "stopped: received={} written={} dropped_rate_limited={} dropped_queue_full={} tcp_rejected={}",
        stats.received.load(Ordering::Relaxed),
        stats.written.load(Ordering::Relaxed),
        stats.dropped_rate_limited.load(Ordering::Relaxed),
        stats.dropped_queue_full.load(Ordering::Relaxed),
        stats.tcp_rejected.load(Ordering::Relaxed),
    );
    Ok(stats)
}

fn spawn<F: FnOnce() + Send + 'static>(name: &str, f: F) -> Result<JoinHandle<()>, String> {
    thread::Builder::new()
        .name(name.into())
        .spawn(f)
        .map_err(|e| format!("cannot spawn {name} thread: {e}"))
}

fn writer_loop(mut router: Router, rx: Receiver<Message>, signals: Signals, stats: Arc<Stats>) {
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(msg) => {
                router.dispatch(&msg);
                let mut n = 1;
                // Drain whatever is queued, then flush once.
                while let Ok(msg) = rx.try_recv() {
                    router.dispatch(&msg);
                    n += 1;
                }
                stats.written.fetch_add(n, Ordering::Relaxed);
                router.flush();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if signals.reopen.swap(false, Ordering::Relaxed) {
            info!("SIGHUP: reopening outputs");
            router.reopen();
        }
    }
    router.flush();
}

fn udp_loop(sock: UdpSocket, tx: SyncSender<Message>, shared: Arc<Shared>) {
    if let Err(e) = sock.set_read_timeout(Some(POLL)) {
        error!("udp: cannot set read timeout: {e}");
        return;
    }
    let mut buf = vec![0u8; UDP_RECV_BUF];
    let mut queue_full_since: Option<Instant> = None;

    while !shared.shutting_down() {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if is_timeout(&e) => continue,
            Err(e) => {
                // e.g. ICMP-induced errors on some platforms; never fatal.
                debug!("udp: recv error: {e}");
                continue;
            }
        };
        if !shared.admit(src) {
            continue;
        }
        let max = shared.max_message_size;
        let msg = parse(
            &buf[..n.min(max)],
            Context {
                received_at: Timestamp::now(),
                source: src,
                transport: Transport::Udp,
                truncated: n > max,
            },
        );
        match tx.try_send(msg) {
            Ok(()) => {
                if let Some(since) = queue_full_since.take() {
                    warn!("udp: queue drained after {:?}", since.elapsed());
                }
            }
            Err(TrySendError::Full(_)) => {
                shared
                    .stats
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                if queue_full_since.is_none() {
                    queue_full_since = Some(Instant::now());
                    warn!("udp: queue full, dropping messages (outputs too slow?)");
                }
            }
            Err(TrySendError::Disconnected(_)) => break,
        }
    }
    debug!("udp listener stopped");
}

fn tcp_accept_loop(
    listener: TcpListener,
    max_connections: usize,
    tx: SyncSender<Message>,
    shared: Arc<Shared>,
) {
    if let Err(e) = listener.set_nonblocking(true) {
        error!("tcp: cannot set non-blocking: {e}");
        return;
    }
    let mut conns: Vec<JoinHandle<()>> = Vec::new();

    while !shared.shutting_down() {
        let (stream, peer) = match listener.accept() {
            Ok(r) => r,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
                continue;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                // EMFILE and friends: back off instead of spinning.
                warn!("tcp: accept failed: {e}");
                thread::sleep(POLL);
                continue;
            }
        };

        start_conn(stream, peer, max_connections, &mut conns, &tx, &shared);
    }

    // Connections the kernel completed but we had not accepted yet may
    // already carry data; take them so a graceful stop loses nothing that
    // was sent before it. Their threads see the shutdown flag and only drain.
    for _ in 0..max_connections {
        match listener.accept() {
            Ok((stream, peer)) => {
                start_conn(stream, peer, max_connections, &mut conns, &tx, &shared)
            }
            Err(_) => break,
        }
    }

    for h in conns {
        let _ = h.join();
    }
    debug!("tcp listener stopped");
}

fn start_conn(
    stream: TcpStream,
    peer: SocketAddr,
    max_connections: usize,
    conns: &mut Vec<JoinHandle<()>>,
    tx: &SyncSender<Message>,
    shared: &Arc<Shared>,
) {
    conns.retain(|h| !h.is_finished());
    if conns.len() >= max_connections {
        shared.stats.tcp_rejected.fetch_add(1, Ordering::Relaxed);
        warn!("tcp: rejecting {peer}: max_connections ({max_connections}) reached");
        return; // dropping `stream` closes it
    }
    let setup = stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(POLL)));
    if let Err(e) = setup {
        warn!("tcp: cannot configure connection from {peer}: {e}");
        return;
    }

    debug!("tcp: connection from {peer}");
    let (tx, shared) = (tx.clone(), shared.clone());
    match spawn("berlog-tcp-conn", move || {
        tcp_conn(stream, peer, tx, shared)
    }) {
        Ok(h) => conns.push(h),
        Err(e) => warn!("tcp: {e}"),
    }
}

fn tcp_conn(mut stream: TcpStream, peer: SocketAddr, tx: SyncSender<Message>, shared: Arc<Shared>) {
    let mut framer = Framer::new(shared.max_message_size);
    let mut buf = vec![0u8; TCP_READ_BUF];
    let mut open = true;

    let deliver = |frame: Frame, open: &mut bool| {
        if !*open || !shared.admit(peer) {
            return;
        }
        let msg = parse(
            &frame.data,
            Context {
                received_at: Timestamp::now(),
                source: peer,
                transport: Transport::Tcp,
                truncated: frame.truncated,
            },
        );
        if tx.send(msg).is_err() {
            *open = false;
        }
    };

    let mut eof = false;
    while open && !shared.shutting_down() {
        match stream.read(&mut buf) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => framer.push(&buf[..n], |f| deliver(f, &mut open)),
            Err(e) if is_timeout(&e) => {}
            Err(e) => {
                debug!("tcp: {peer}: read error: {e}");
                eof = true;
                break;
            }
        }
    }
    // On shutdown, take what the kernel has already buffered for us, without
    // waiting for more and bounded so a fast sender cannot stall the exit.
    if open && !eof && stream.set_nonblocking(true).is_ok() {
        let mut budget = SHUTDOWN_DRAIN_BYTES;
        while open && budget > 0 {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    budget = budget.saturating_sub(n);
                    framer.push(&buf[..n], |f| deliver(f, &mut open));
                }
            }
        }
    }
    if let Some(frame) = framer.finish() {
        deliver(frame, &mut open);
    }
    debug!("tcp: {peer} closed");
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}
