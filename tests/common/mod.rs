//! Helpers for spawning the berlog binary on ephemeral localhost ports.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_secs(10);

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_berlog")
}

/// A fresh, empty directory under cargo's per-target tmpdir.
pub fn temp_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub struct Daemon {
    child: Option<Child>,
    pub dir: PathBuf,
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    stderr: Arc<Mutex<Vec<String>>>,
}

impl Daemon {
    /// Start berlog with `body` appended to a config that listens on
    /// 127.0.0.1:0 for both UDP and TCP. `{dir}` in `body` is replaced with
    /// the test's temp dir. Blocks until the daemon reports `ready`.
    pub fn start(name: &str, body: &str) -> Daemon {
        Self::start_raw(
            name,
            &format!("[udp]\naddress = \"127.0.0.1:0\"\n[tcp]\naddress = \"127.0.0.1:0\"\n{body}"),
        )
    }

    pub fn start_raw(name: &str, config: &str) -> Daemon {
        let dir = temp_dir(name);
        let config = config.replace("{dir}", dir.to_str().unwrap());
        let path = dir.join("berlog.toml");
        std::fs::write(&path, config).unwrap();

        let mut child = Command::new(bin())
            .arg("-c")
            .arg(&path)
            .env("BERLOG_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn berlog");

        let stderr = Arc::new(Mutex::new(Vec::new()));
        let reader = BufReader::new(child.stderr.take().unwrap());
        let sink = stderr.clone();
        thread::spawn(move || {
            for line in reader.lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });

        let mut d = Daemon {
            child: Some(child),
            dir,
            udp: None,
            tcp: None,
            stderr,
        };
        let deadline = Instant::now() + TIMEOUT;
        loop {
            {
                let lines = d.stderr.lock().unwrap();
                for l in lines.iter() {
                    if let Some(a) = l.split("listening on udp ").nth(1) {
                        d.udp = Some(a.trim().parse().unwrap());
                    }
                    if let Some(a) = l.split("listening on tcp ").nth(1) {
                        d.tcp = Some(a.trim().parse().unwrap());
                    }
                }
                if lines.iter().any(|l| l.ends_with("INFO: ready")) {
                    break;
                }
            }
            if let Some(status) = d.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("berlog exited early ({status}):\n{}", d.stderr_text());
            }
            assert!(
                Instant::now() < deadline,
                "berlog never became ready:\n{}",
                d.stderr_text()
            );
            thread::sleep(Duration::from_millis(20));
        }
        d
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    pub fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(self.pid().to_string())
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill -{sig} failed");
    }

    pub fn stderr_text(&self) -> String {
        self.stderr.lock().unwrap().join("\n")
    }

    pub fn wait_for_stderr(&self, needle: &str) {
        let deadline = Instant::now() + TIMEOUT;
        while !self.stderr_text().contains(needle) {
            assert!(
                Instant::now() < deadline,
                "stderr never contained {needle:?}:\n{}",
                self.stderr_text()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// SIGTERM, wait for exit, return (status, stdout, stderr).
    pub fn stop(mut self) -> (ExitStatus, String, String) {
        self.signal("TERM");
        let mut child = self.child.take().unwrap();
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("berlog did not exit after SIGTERM:\n{}", self.stderr_text());
            }
            thread::sleep(Duration::from_millis(20));
        };
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        // Give the stderr reader a moment to collect the final lines.
        thread::sleep(Duration::from_millis(100));
        (status, out, self.stderr_text())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Read `path` until it has at least `n` lines (or time out).
pub fn wait_lines(path: &Path, n: usize) -> Vec<String> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let lines = read_lines(path);
        if lines.len() >= n {
            return lines;
        }
        assert!(
            Instant::now() < deadline,
            "{} has {} lines, expected {n}:\n{}",
            path.display(),
            lines.len(),
            lines.join("\n")
        );
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

pub fn json_lines(path: &Path, n: usize) -> Vec<serde_json::Value> {
    wait_lines(path, n)
        .iter()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad json {l:?}: {e}")))
        .collect()
}

/// Find the record whose `message` equals `msg`.
pub fn find<'a>(records: &'a [serde_json::Value], msg: &str) -> &'a serde_json::Value {
    records
        .iter()
        .find(|r| r["message"] == msg)
        .unwrap_or_else(|| panic!("no record with message {msg:?} in {records:#?}"))
}
