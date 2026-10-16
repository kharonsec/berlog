//! End-to-end tests: spawn the real binary, send traffic over loopback,
//! assert on what lands in the output files.

mod common;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::Duration;

use common::*;

fn udp_send(d: &Daemon, payload: &[u8]) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.send_to(payload, d.udp.unwrap()).unwrap();
}

fn tcp(d: &Daemon) -> TcpStream {
    let s = TcpStream::connect(d.tcp.unwrap()).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Write in pieces with pauses so the daemon sees partial reads.
fn write_in_pieces(s: &mut TcpStream, data: &[u8], cuts: &[usize]) {
    let mut start = 0;
    for &c in cuts.iter().chain(std::iter::once(&data.len())) {
        s.write_all(&data[start..c]).unwrap();
        s.flush().unwrap();
        thread::sleep(Duration::from_millis(30));
        start = c;
    }
}

#[test]
fn routes_udp_and_tcp_in_both_framings() {
    let d = Daemon::start(
        "routing",
        r#"
        [[rule]]
        name = "auth"
        facility = ["auth", "authpriv"]
        outputs = [{ type = "file", path = "{dir}/auth.log", format = "text" }]

        [[rule]]
        name = "errors"
        severity = "err"
        outputs = [
          { type = "file", path = "{dir}/errors.jsonl" },
          { type = "stdout", format = "text" },
        ]

        [default]
        outputs = [{ type = "file", path = "{dir}/all.jsonl" }]
        "#,
    );

    // UDP, RFC 3164, auth.warning → auth.log only.
    udp_send(
        &d,
        b"<36>Oct 16 10:00:00 bastion sshd[77]: Failed password for root\n",
    );

    // TCP, LF framing, split mid-message.
    let mut lf = tcp(&d);
    let data = b"<14>Oct 16 10:00:01 web1 nginx: lf one\n<11>1 2026-10-16T10:00:02Z web1 app - - - lf two err\n";
    write_in_pieces(&mut lf, data, &[10, 45]);
    drop(lf);

    // TCP, octet counting, split mid-length-header and mid-payload.
    let m1 = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] octet one";
    let m2 = b"<14>1 - host2 app2 99 - - octet\ntwo with newline";
    let mut framed = Vec::new();
    for m in [&m1[..], &m2[..]] {
        framed.extend_from_slice(format!("{} ", m.len()).as_bytes());
        framed.extend_from_slice(m);
    }
    let mut oc = tcp(&d);
    write_in_pieces(&mut oc, &framed, &[1, 2, 50, m1.len() + 4 + 1]);
    drop(oc);

    // Garbage: still delivered, marked unparsed.
    udp_send(&d, b"\x00\xffnot syslog at all");

    let all = json_lines(&d.path("all.jsonl"), 4);
    let errors = json_lines(&d.path("errors.jsonl"), 1);
    let auth = wait_lines(&d.path("auth.log"), 1);
    let (status, stdout, _) = d.stop();
    assert!(status.success(), "{status}");

    assert_eq!(auth.len(), 1);
    assert!(
        auth[0].ends_with(" bastion auth.warning sshd[77]: Failed password for root"),
        "{}",
        auth[0]
    );

    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["message"], "lf two err");
    assert_eq!(errors[0]["parse_status"], "rfc5424");
    assert!(
        stdout.ends_with("web1 user.err app: lf two err\n"),
        "{stdout:?}"
    );

    assert_eq!(all.len(), 4, "{all:#?}");
    let lf1 = find(&all, "lf one");
    assert_eq!(lf1["transport"], "tcp");
    assert_eq!(lf1["hostname"], "web1");
    assert_eq!(lf1["appname"], "nginx");
    assert_eq!(lf1["parse_status"], "rfc3164");

    let o1 = find(&all, "octet one");
    assert_eq!(o1["timestamp"], "2003-10-11T22:14:15.003000Z");
    assert_eq!(o1["facility"], "local4");
    assert_eq!(o1["msgid"], "ID47");
    assert_eq!(o1["structured_data"]["exampleSDID@32473"]["iut"], "3");

    let o2 = find(&all, "octet\ntwo with newline");
    assert_eq!(o2["procid"], "99");
    assert_eq!(o2["hostname"], "host2");

    let g = find(&all, "\u{0}\u{FFFD}not syslog at all");
    assert_eq!(g["parse_status"], "unparsed");
    assert_eq!(g["transport"], "udp");
    assert_eq!(g["facility"], "user");
    assert_eq!(g["severity"], "notice");
}

#[test]
fn oversized_frames_are_truncated_and_stream_survives() {
    let d = Daemon::start(
        "oversized",
        r#"
        [server]
        max_message_size = 512
        [default]
        outputs = [{ type = "file", path = "{dir}/all.jsonl" }]
        "#,
    );

    // Octet-counted frame of 5000 bytes, then a normal one, same connection.
    let big = format!("<13>1 - h a - - - {}", "A".repeat(5000 - 18));
    assert_eq!(big.len(), 5000);
    let mut s = tcp(&d);
    s.write_all(format!("{} {big}", big.len()).as_bytes())
        .unwrap();
    s.write_all(b"20 <13>1 - h a - - - ok").unwrap();
    drop(s);

    // LF framing: oversized line followed by a normal one.
    let mut s = tcp(&d);
    s.write_all(format!("<13>{}\n<13>after-long-line\n", "B".repeat(3000)).as_bytes())
        .unwrap();
    drop(s);

    // UDP: an 8 KiB+ datagram.
    udp_send(&d, format!("<13>{}", "C".repeat(9000)).as_bytes());

    let all = json_lines(&d.path("all.jsonl"), 5);
    assert!(d.stop().0.success());

    let truncated: Vec<_> = all.iter().filter(|r| r["truncated"] == true).collect();
    assert_eq!(truncated.len(), 3, "{all:#?}");
    for r in &truncated {
        // The parsed message can never exceed the configured payload limit.
        assert!(r["message"].as_str().unwrap().len() <= 512);
    }
    assert_eq!(find(&all, "ok")["truncated"], false);
    assert_eq!(find(&all, "after-long-line")["truncated"], false);
}

#[test]
fn connection_closed_mid_frame_delivers_partial_message() {
    let d = Daemon::start(
        "midframe",
        r#"
        [default]
        outputs = [{ type = "file", path = "{dir}/all.jsonl" }]
        "#,
    );
    // Closed in the middle of an octet-counted payload.
    let mut s = tcp(&d);
    s.write_all(b"100 <13>1 - h a - - - partial").unwrap();
    drop(s);
    // Closed in the middle of the octet count itself, after a full frame.
    let mut s = tcp(&d);
    s.write_all(b"7 <13>one12").unwrap();
    drop(s);

    let all = json_lines(&d.path("all.jsonl"), 3);
    assert!(d.stop().0.success());

    let p = find(&all, "partial");
    assert_eq!(p["truncated"], true);
    assert_eq!(p["parse_status"], "rfc5424");
    assert_eq!(find(&all, "one")["truncated"], false);
    let tail = find(&all, "12");
    assert_eq!(tail["truncated"], true);
    assert_eq!(tail["parse_status"], "unparsed");
}

#[test]
fn rate_limit_per_source() {
    let d = Daemon::start(
        "ratelimit",
        r#"
        [rate_limit]
        messages_per_second = 1
        burst = 5
        [default]
        outputs = [{ type = "file", path = "{dir}/all.jsonl" }]
        "#,
    );
    let mut s = tcp(&d);
    let mut payload = Vec::new();
    for i in 0..50 {
        payload.extend_from_slice(format!("<13>1 - h a - - - msg {i}\n").as_bytes());
    }
    s.write_all(&payload).unwrap();
    drop(s);

    d.wait_for_stderr("rate limit: dropping messages from 127.0.0.1");
    let lines = wait_lines(&d.path("all.jsonl"), 5);
    thread::sleep(Duration::from_millis(300));
    let lines_after = read_lines(&d.path("all.jsonl"));
    let (status, _, _) = d.stop();
    assert!(status.success());
    // Burst of 5, plus at most one refill token in the time the test takes.
    assert!(
        (5..=6).contains(&lines_after.len()),
        "{} lines: {lines_after:#?}",
        lines.len()
    );
}

#[test]
fn sigterm_drains_buffered_tcp_data_and_flushes() {
    let d = Daemon::start(
        "shutdown",
        r#"
        [default]
        outputs = [{ type = "file", path = "{dir}/all.jsonl" }]
        "#,
    );
    let path = d.path("all.jsonl");
    for i in 0..10 {
        udp_send(&d, format!("<13>1 - h a - - - u{i}").as_bytes());
    }
    wait_lines(&path, 10);

    // 2000 octet-counted frames plus an unterminated LF-style tail would be
    // a framing mix, so use a second connection for the tail.
    let mut bulk = tcp(&d);
    let mut payload = Vec::new();
    for i in 0..2000 {
        let m = format!("<13>1 - h a - - - n{i}");
        payload.extend_from_slice(format!("{} {m}", m.len()).as_bytes());
    }
    bulk.write_all(&payload).unwrap();
    let mut tail = tcp(&d);
    tail.write_all(b"<13>1 - h a - - - last words").unwrap(); // no LF, stays open

    // Both connections stay open across the SIGTERM.
    let (status, _, stderr) = d.stop();
    drop((bulk, tail));
    assert!(status.success(), "{status}");

    let lines = read_lines(&path);
    assert_eq!(lines.len(), 2011, "stderr:\n{stderr}");
    assert!(lines.iter().any(|l| l.contains("\"last words\"")));
    assert!(lines.iter().any(|l| l.contains("\"n1999\"")));
    assert!(stderr.contains("received=2011 written=2011"), "{stderr}");
}

#[test]
fn sighup_reopens_outputs() {
    let d = Daemon::start(
        "sighup",
        r#"
        [default]
        outputs = [{ type = "file", path = "{dir}/all.log", format = "text" }]
        "#,
    );
    let path = d.path("all.log");
    udp_send(&d, b"<13>1 - h a - - - before");
    wait_lines(&path, 1);
    std::fs::rename(&path, d.path("all.log.1")).unwrap();
    d.signal("HUP");
    d.wait_for_stderr("reopened");
    udp_send(&d, b"<13>1 - h a - - - after");
    let lines = wait_lines(&path, 1);
    assert!(lines[0].ends_with("after"), "{lines:?}");
    let rotated = read_lines(&d.path("all.log.1"));
    assert!(rotated[0].ends_with("before"));
    assert!(d.stop().0.success());
}

#[test]
fn max_connections_is_enforced() {
    let d = Daemon::start_raw(
        "maxconn",
        r#"
        [udp]
        enabled = false
        [tcp]
        address = "127.0.0.1:0"
        max_connections = 2
        [default]
        outputs = [{ type = "file", path = "{dir}/all.jsonl" }]
        "#,
    );
    let a = tcp(&d);
    let b = tcp(&d);
    d.wait_for_stderr("connection from");
    thread::sleep(Duration::from_millis(200));
    let mut c = tcp(&d);
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 1];
    // The third connection is accepted and immediately closed.
    assert_eq!(c.read(&mut buf).unwrap_or(0), 0);
    d.wait_for_stderr("max_connections (2) reached");
    drop((a, b));
    assert!(d.stop().0.success());
}

#[test]
fn works_with_util_linux_logger() {
    if Command::new("logger").arg("--version").output().is_err() {
        eprintln!("logger not installed; skipping");
        return;
    }
    let d = Daemon::start(
        "logger",
        r#"
        [default]
        outputs = [{ type = "file", path = "{dir}/all.jsonl" }]
        "#,
    );
    let udp_port = d.udp.unwrap().port().to_string();
    let tcp_port = d.tcp.unwrap().port().to_string();
    let run = |args: &[&str]| {
        let ok = Command::new("logger")
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "logger {args:?}");
    };
    run(&[
        "-n",
        "127.0.0.1",
        "-P",
        &udp_port,
        "-d",
        "-p",
        "local0.info",
        "-t",
        "lg",
        "via udp",
    ]);
    run(&[
        "-n",
        "127.0.0.1",
        "-P",
        &tcp_port,
        "-T",
        "--octet-count",
        "-p",
        "daemon.err",
        "-t",
        "lg",
        "via tcp octet",
    ]);
    run(&[
        "-n",
        "127.0.0.1",
        "-P",
        &tcp_port,
        "-T",
        "--rfc3164",
        "-p",
        "user.notice",
        "-t",
        "lg",
        "via tcp 3164",
    ]);

    let all = json_lines(&d.path("all.jsonl"), 3);
    assert!(d.stop().0.success());
    let u = find(&all, "via udp");
    assert_eq!(
        (u["facility"].as_str(), u["severity"].as_str()),
        (Some("local0"), Some("info"))
    );
    assert_eq!(u["appname"], "lg");
    let t = find(&all, "via tcp octet");
    assert_eq!(t["parse_status"], "rfc5424");
    assert_eq!(t["facility"], "daemon");
    let b = find(&all, "via tcp 3164");
    assert_eq!(b["parse_status"], "rfc3164");
    assert_eq!(b["appname"], "lg");
}
