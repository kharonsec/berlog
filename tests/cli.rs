//! Command-line behavior: -t, --version, usage errors, fail-closed startup.

mod common;

use std::process::{Command, Output};

use common::{bin, temp_dir};

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn version_flag() {
    for flag in ["--version", "-V"] {
        let o = run(&[flag]);
        assert!(o.status.success());
        assert_eq!(
            String::from_utf8_lossy(&o.stdout),
            format!("berlog {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn help_flag() {
    let o = run(&["--help"]);
    assert!(o.status.success());
    assert!(text(&o).contains("Usage: berlog"));
}

#[test]
fn unknown_argument_is_a_usage_error() {
    let o = run(&["--frobnicate"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o).contains("unexpected argument"));
    let o = run(&["-c"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn config_test_success() {
    let dir = temp_dir("cli-ok");
    let cfg = dir.join("ok.toml");
    std::fs::write(
        &cfg,
        format!(
            "[default]\noutputs = [{{ type = \"file\", path = \"{}/out/all.jsonl\" }}]\n",
            dir.display()
        ),
    )
    .unwrap();
    let o = run(&["-t", "-c", cfg.to_str().unwrap()]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("test is successful"));
    // -t opens outputs (creating directories), like nginx -t.
    assert!(dir.join("out/all.jsonl").exists());
}

#[test]
fn config_test_failures() {
    let dir = temp_dir("cli-bad");
    let cases = [
        (
            "typo.toml",
            "[udp]\nadress = \"0.0.0.0:5514\"\n",
            "unknown field",
        ),
        (
            "regex.toml",
            "[[rule]]\nhostname = \"[\"\noutputs = [{type=\"stdout\"}]\n",
            "invalid hostname regex",
        ),
        (
            "unwritable.toml",
            "[default]\noutputs = [{type=\"file\", path=\"/proc/nope/x.log\"}]\n",
            "cannot open output",
        ),
    ];
    for (name, body, needle) in cases {
        let cfg = dir.join(name);
        std::fs::write(&cfg, body).unwrap();
        let o = run(&["-t", "-c", cfg.to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(1), "{name}: {}", text(&o));
        assert!(text(&o).contains(needle), "{name}: {}", text(&o));
    }
    let o = run(&["-t", "-c", dir.join("missing.toml").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o).contains("cannot read"));
}

#[test]
fn bad_config_refuses_to_start() {
    // Without -t: must exit non-zero rather than start half-configured.
    let dir = temp_dir("cli-start");
    let cfg = dir.join("bad.toml");
    std::fs::write(
        &cfg,
        "[[rule]]\nseverity = \"loud\"\noutputs = [{type=\"stdout\"}]\n",
    )
    .unwrap();
    let o = run(&["-c", cfg.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o).contains("unknown severity"));
}

#[test]
fn port_in_use_refuses_to_start() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = temp_dir("cli-port");
    let cfg = dir.join("b.toml");
    std::fs::write(
        &cfg,
        format!(
            "[udp]\nenabled = false\n[tcp]\naddress = \"{}\"\n[default]\noutputs = [{{type=\"stdout\"}}]\n",
            taken.local_addr().unwrap()
        ),
    )
    .unwrap();
    let o = run(&["-c", cfg.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o).contains("cannot bind tcp"), "{}", text(&o));
}

#[test]
fn shipped_example_config_is_valid() {
    let example = concat!(env!("CARGO_MANIFEST_DIR"), "/berlog.example.toml");
    let text = std::fs::read_to_string(example).unwrap();
    berlog::config::Config::from_toml(&text).unwrap();
}
