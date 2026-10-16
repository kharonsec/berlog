#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use berlog::config::{Config, DEFAULT_CONFIG_PATH};
use berlog::daemon::{self, Signals};
use berlog::router::Router;
use berlog::{error, info};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage: berlog [-c CONFIG] [-t]

A minimal syslog daemon.

Options:
  -c, --config PATH   configuration file (default: /etc/berlog/berlog.toml)
  -t, --test          check the configuration and outputs, then exit
  -V, --version       print version and exit
  -h, --help          print this help and exit

Environment:
  BERLOG_LOG          diagnostics level: error, warn, info (default), debug

Signals:
  SIGTERM, SIGINT     flush outputs and exit (a second one exits immediately)
  SIGHUP              reopen output files (for log rotation)
";

struct Args {
    config: PathBuf,
    test: bool,
}

enum Cli {
    Run(Args),
    Exit(ExitCode),
}

fn parse_args() -> Cli {
    let mut config = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut test = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-c" | "--config") => match args.next() {
                Some(p) => config = PathBuf::from(p),
                None => return usage_error("-c requires a path"),
            },
            Some("-t" | "--test") => test = true,
            Some("-V" | "--version") => {
                println!("berlog {VERSION}");
                return Cli::Exit(ExitCode::SUCCESS);
            }
            Some("-h" | "--help") => {
                print!("{USAGE}");
                return Cli::Exit(ExitCode::SUCCESS);
            }
            _ => return usage_error(&format!("unexpected argument {arg:?}")),
        }
    }
    Cli::Run(Args { config, test })
}

fn usage_error(msg: &str) -> Cli {
    eprintln!("berlog: {msg}\n\n{USAGE}");
    Cli::Exit(ExitCode::from(2))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Cli::Run(a) => a,
        Cli::Exit(code) => return code,
    };
    if let Err(e) = berlog::diag::init_from_env() {
        eprintln!("berlog: {e}");
        return ExitCode::from(2);
    }

    let path = args.config.display().to_string();
    let config = match std::fs::read_to_string(&args.config)
        .map_err(|e| format!("cannot read {path}: {e}"))
        .and_then(|text| Config::from_toml(&text).map_err(|e| format!("{path}: {e}")))
    {
        Ok(c) => c,
        Err(e) => {
            error!("configuration error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if args.test {
        // Like `nginx -t`: also open every output, so permission problems
        // surface now rather than at startup.
        return match Router::new(config) {
            Ok(_) => {
                println!("berlog: configuration file {path} test is successful");
                ExitCode::SUCCESS
            }
            Err(e) => {
                error!("configuration test failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    info!(
        "berlog {VERSION} starting (config {path}, {} rule(s), udp {}, tcp {}, rate limit {})",
        config.rules.len(),
        config.udp.map_or("off".into(), |a| a.to_string()),
        config
            .tcp
            .as_ref()
            .map_or("off".into(), |t| t.address.to_string()),
        config.rate_limit.map_or("off".into(), |r| format!(
            "{}/s burst {}",
            r.messages_per_second, r.burst
        )),
    );

    let signals = Signals::default();
    if let Err(e) = register_signals(&signals) {
        error!("cannot install signal handlers: {e}");
        return ExitCode::FAILURE;
    }

    match daemon::run(config, signals) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn register_signals(s: &Signals) -> std::io::Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::flag;
    for sig in [SIGTERM, SIGINT] {
        // Order matters: the conditional exit fires only if the flag is
        // already set, i.e. on the second signal.
        flag::register_conditional_shutdown(sig, 1, s.shutdown.clone())?;
        flag::register(sig, s.shutdown.clone())?;
    }
    flag::register(SIGHUP, s.reopen.clone())?;
    Ok(())
}
