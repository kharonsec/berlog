//! Configuration: TOML schema, defaults and validation.
//!
//! Loading is fail-closed. Unknown keys, unknown facility/severity names,
//! invalid regexes, invalid addresses and inconsistent outputs are all errors,
//! so berlog never starts half-configured. See README.md for the reference.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;

use crate::message::{Facility, Severity};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/berlog/berlog.toml";
pub const DEFAULT_ADDRESS: &str = "0.0.0.0:5514";
pub const DEFAULT_OUTPUT_PATH: &str = "/var/log/berlog/messages.jsonl";

/// Validated, ready-to-use configuration.
#[derive(Debug)]
pub struct Config {
    pub max_message_size: usize,
    pub queue_size: usize,
    pub udp: Option<SocketAddr>,
    pub tcp: Option<TcpConfig>,
    pub rate_limit: Option<RateLimitConfig>,
    pub rules: Vec<Rule>,
    pub default_outputs: Vec<OutputSpec>,
}

#[derive(Debug, Clone)]
pub struct TcpConfig {
    pub address: SocketAddr,
    pub max_connections: usize,
    /// Close a connection that sends nothing for this long. `None` disables.
    pub idle_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitConfig {
    pub messages_per_second: f64,
    pub burst: f64,
}

#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub facilities: Option<Vec<Facility>>,
    pub severity: Option<SeverityMatch>,
    pub hostname: Option<Regex>,
    pub appname: Option<Regex>,
    pub stop: bool,
    pub outputs: Vec<OutputSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeverityMatch {
    /// This severity or anything more severe (`"warning"`).
    AtLeast(Severity),
    /// Exactly this severity (`"=warning"`).
    Exactly(Severity),
}

impl SeverityMatch {
    pub fn matches(self, s: Severity) -> bool {
        match self {
            SeverityMatch::AtLeast(t) => s.at_least(t),
            SeverityMatch::Exactly(t) => s == t,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Jsonl,
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OutputSpec {
    File { path: PathBuf, format: Format },
    Stdout { format: Format },
}

#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

// ---------------------------------------------------------------- raw schema

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    server: RawServer,
    #[serde(default)]
    udp: RawUdp,
    #[serde(default)]
    tcp: RawTcp,
    rate_limit: Option<RawRateLimit>,
    #[serde(default)]
    rule: Vec<RawRule>,
    default: Option<RawDefault>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawServer {
    max_message_size: usize,
    queue_size: usize,
}

impl Default for RawServer {
    fn default() -> Self {
        RawServer {
            max_message_size: 64 * 1024,
            queue_size: 10_000,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawUdp {
    enabled: bool,
    address: String,
}

impl Default for RawUdp {
    fn default() -> Self {
        RawUdp {
            enabled: true,
            address: DEFAULT_ADDRESS.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawTcp {
    enabled: bool,
    address: String,
    max_connections: usize,
    idle_timeout_secs: u64,
}

impl Default for RawTcp {
    fn default() -> Self {
        RawTcp {
            enabled: true,
            address: DEFAULT_ADDRESS.into(),
            max_connections: 256,
            idle_timeout_secs: 300,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRateLimit {
    #[serde(default = "yes")]
    enabled: bool,
    messages_per_second: f64,
    burst: Option<f64>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    name: Option<String>,
    facility: Option<OneOrMany>,
    severity: Option<String>,
    hostname: Option<String>,
    appname: Option<String>,
    #[serde(default)]
    stop: bool,
    outputs: Vec<RawOutput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefault {
    outputs: Vec<RawOutput>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum RawOutput {
    File {
        path: PathBuf,
        #[serde(default)]
        format: Option<Format>,
    },
    Stdout {
        #[serde(default)]
        format: Option<Format>,
    },
}

// ---------------------------------------------------------------- compile

impl Config {
    /// Parse and validate a TOML configuration document.
    pub fn from_toml(text: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig =
            toml::from_str(text).map_err(|e| ConfigError(format!("invalid TOML: {e}")))?;
        Self::compile(raw)
    }

    /// All distinct outputs referenced by rules and the default route.
    pub fn all_outputs(&self) -> Vec<&OutputSpec> {
        let mut seen = Vec::new();
        for spec in self
            .rules
            .iter()
            .flat_map(|r| r.outputs.iter())
            .chain(self.default_outputs.iter())
        {
            if !seen.contains(&spec) {
                seen.push(spec);
            }
        }
        seen
    }

    fn compile(raw: RawConfig) -> Result<Config, ConfigError> {
        let max_message_size = raw.server.max_message_size;
        if !(480..=16 * 1024 * 1024).contains(&max_message_size) {
            // RFC 5424 section 6.1: receivers MUST accept 480 octets.
            return err("server.max_message_size must be between 480 and 16777216");
        }
        if raw.server.queue_size == 0 {
            return err("server.queue_size must be at least 1");
        }

        let udp = if raw.udp.enabled {
            Some(parse_addr("udp.address", &raw.udp.address)?)
        } else {
            None
        };
        let tcp = if raw.tcp.enabled {
            if raw.tcp.max_connections == 0 {
                return err("tcp.max_connections must be at least 1");
            }
            Some(TcpConfig {
                address: parse_addr("tcp.address", &raw.tcp.address)?,
                max_connections: raw.tcp.max_connections,
                idle_timeout: (raw.tcp.idle_timeout_secs > 0)
                    .then(|| Duration::from_secs(raw.tcp.idle_timeout_secs)),
            })
        } else {
            None
        };
        if udp.is_none() && tcp.is_none() {
            return err("both udp and tcp listeners are disabled; nothing to do");
        }

        let rate_limit = match raw.rate_limit {
            Some(rl) if rl.enabled => {
                let rate = rl.messages_per_second;
                let burst = rl.burst.unwrap_or(rate);
                if !(rate.is_finite() && rate > 0.0) {
                    return err("rate_limit.messages_per_second must be a positive number");
                }
                if !(burst.is_finite() && burst >= 1.0) {
                    return err("rate_limit.burst must be at least 1");
                }
                Some(RateLimitConfig {
                    messages_per_second: rate,
                    burst,
                })
            }
            _ => None,
        };

        let mut rules = Vec::with_capacity(raw.rule.len());
        for (i, r) in raw.rule.into_iter().enumerate() {
            rules.push(compile_rule(i, r)?);
        }

        let default_outputs = match raw.default {
            Some(d) => compile_outputs("default", d.outputs)?,
            None => vec![OutputSpec::File {
                path: DEFAULT_OUTPUT_PATH.into(),
                format: Format::Jsonl,
            }],
        };

        let config = Config {
            max_message_size,
            queue_size: raw.server.queue_size,
            udp,
            tcp,
            rate_limit,
            rules,
            default_outputs,
        };

        // One file, one format: two rules writing JSON and text interleaved
        // into the same file is always a mistake.
        let mut formats: HashMap<&PathBuf, Format> = HashMap::new();
        for spec in config.all_outputs() {
            if let OutputSpec::File { path, format } = spec {
                if let Some(prev) = formats.insert(path, *format) {
                    if prev != *format {
                        return err(format!(
                            "file {} is used with both jsonl and text formats",
                            path.display()
                        ));
                    }
                }
            }
        }

        Ok(config)
    }
}

fn parse_addr(key: &str, s: &str) -> Result<SocketAddr, ConfigError> {
    s.parse()
        .map_err(|_| ConfigError(format!("{key}: {s:?} is not a valid IP:port address")))
}

fn compile_rule(index: usize, r: RawRule) -> Result<Rule, ConfigError> {
    let name = r.name.unwrap_or_else(|| format!("rule-{}", index + 1));
    let ctx = format!("rule {name:?}");

    let facilities = match r.facility {
        None => None,
        Some(f) => {
            let names = match f {
                OneOrMany::One(s) => vec![s],
                OneOrMany::Many(v) => v,
            };
            if names.is_empty() {
                return err(format!("{ctx}: facility list is empty"));
            }
            let mut out = Vec::new();
            for n in names {
                match Facility::from_name(&n) {
                    Some(f) => out.push(f),
                    None => return err(format!("{ctx}: unknown facility {n:?}")),
                }
            }
            Some(out)
        }
    };

    let severity = match r.severity {
        None => None,
        Some(s) => {
            let (exact, name) = match s.strip_prefix('=') {
                Some(rest) => (true, rest),
                None => (false, s.as_str()),
            };
            let sev = Severity::from_name(name.trim())
                .ok_or_else(|| ConfigError(format!("{ctx}: unknown severity {s:?}")))?;
            Some(if exact {
                SeverityMatch::Exactly(sev)
            } else {
                SeverityMatch::AtLeast(sev)
            })
        }
    };

    let regex = |field: &str, pat: Option<String>| -> Result<Option<Regex>, ConfigError> {
        pat.map(|p| {
            Regex::new(&p).map_err(|e| ConfigError(format!("{ctx}: invalid {field} regex: {e}")))
        })
        .transpose()
    };

    Ok(Rule {
        hostname: regex("hostname", r.hostname)?,
        appname: regex("appname", r.appname)?,
        outputs: compile_outputs(&ctx, r.outputs)?,
        name,
        facilities,
        severity,
        stop: r.stop,
    })
}

fn compile_outputs(ctx: &str, raw: Vec<RawOutput>) -> Result<Vec<OutputSpec>, ConfigError> {
    if raw.is_empty() {
        return err(format!("{ctx}: at least one output is required"));
    }
    raw.into_iter()
        .map(|o| match o {
            RawOutput::File { path, format } => {
                if path.as_os_str().is_empty() {
                    return err(format!("{ctx}: file output has an empty path"));
                }
                Ok(OutputSpec::File {
                    path,
                    format: format.unwrap_or(Format::Jsonl),
                })
            }
            RawOutput::Stdout { format } => Ok(OutputSpec::Stdout {
                format: format.unwrap_or(Format::Text),
            }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bad(text: &str, needle: &str) {
        match Config::from_toml(text) {
            Ok(_) => panic!("config should be rejected:\n{text}"),
            Err(e) => assert!(
                e.to_string().contains(needle),
                "error {e:?} does not mention {needle:?}"
            ),
        }
    }

    #[test]
    fn empty_config_uses_defaults() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.udp, Some(DEFAULT_ADDRESS.parse().unwrap()));
        assert_eq!(c.tcp.as_ref().unwrap().max_connections, 256);
        assert_eq!(
            c.tcp.as_ref().unwrap().idle_timeout,
            Some(Duration::from_secs(300))
        );
        assert_eq!(c.max_message_size, 65536);
        assert!(c.rate_limit.is_none());
        assert!(c.rules.is_empty());
        assert_eq!(
            c.default_outputs,
            vec![OutputSpec::File {
                path: DEFAULT_OUTPUT_PATH.into(),
                format: Format::Jsonl
            }]
        );
    }

    #[test]
    fn full_config() {
        let c = Config::from_toml(
            r#"
            [server]
            max_message_size = 8192
            queue_size = 100

            [udp]
            address = "127.0.0.1:0"

            [tcp]
            enabled = false

            [rate_limit]
            messages_per_second = 50
            burst = 100

            [[rule]]
            name = "auth"
            facility = ["auth", "authpriv"]
            severity = "warning"
            hostname = '^web\d+$'
            appname = "^sshd$"
            stop = true
            outputs = [
              { type = "file", path = "/tmp/auth.log", format = "text" },
              { type = "stdout" },
            ]

            [[rule]]
            facility = "kern"
            severity = "=err"
            outputs = [{ type = "file", path = "/tmp/kern.jsonl" }]

            [default]
            outputs = [{ type = "stdout", format = "jsonl" }]
            "#,
        )
        .unwrap();
        assert_eq!(c.max_message_size, 8192);
        assert!(c.tcp.is_none());
        assert_eq!(
            c.rate_limit,
            Some(RateLimitConfig {
                messages_per_second: 50.0,
                burst: 100.0
            })
        );
        let auth = &c.rules[0];
        assert_eq!(
            auth.facilities,
            Some(vec![
                Facility::AUTH,
                Facility::from_name("authpriv").unwrap()
            ])
        );
        assert_eq!(
            auth.severity,
            Some(SeverityMatch::AtLeast(Severity::WARNING))
        );
        assert!(auth.hostname.as_ref().unwrap().is_match("web12"));
        assert!(auth.stop);
        assert_eq!(
            auth.outputs[1],
            OutputSpec::Stdout {
                format: Format::Text
            }
        );
        let kern = &c.rules[1];
        assert_eq!(kern.name, "rule-2");
        assert_eq!(kern.severity, Some(SeverityMatch::Exactly(Severity::ERR)));
        assert_eq!(
            kern.outputs[0],
            OutputSpec::File {
                path: "/tmp/kern.jsonl".into(),
                format: Format::Jsonl
            }
        );
        assert_eq!(
            c.default_outputs,
            vec![OutputSpec::Stdout {
                format: Format::Jsonl
            }]
        );
        assert_eq!(c.all_outputs().len(), 4);
    }

    #[test]
    fn tcp_idle_timeout() {
        let c = Config::from_toml("[tcp]\nidle_timeout_secs = 2").unwrap();
        assert_eq!(c.tcp.unwrap().idle_timeout, Some(Duration::from_secs(2)));
        let c = Config::from_toml("[tcp]\nidle_timeout_secs = 0").unwrap();
        assert_eq!(c.tcp.unwrap().idle_timeout, None);
        bad("[tcp]\nidle_timeout_secs = -1", "invalid TOML");
    }

    #[test]
    fn severity_matching() {
        let at_least = SeverityMatch::AtLeast(Severity::WARNING);
        assert!(at_least.matches(Severity::EMERG));
        assert!(at_least.matches(Severity::WARNING));
        assert!(!at_least.matches(Severity::NOTICE));
        let exact = SeverityMatch::Exactly(Severity::WARNING);
        assert!(exact.matches(Severity::WARNING));
        assert!(!exact.matches(Severity::ERR));
    }

    #[test]
    fn rejects_invalid_configs() {
        bad("[udp]\nadress = \"x\"", "unknown field");
        bad("bogus = 1", "unknown field");
        bad("[udp]\naddress = \"localhost:514\"", "not a valid IP:port");
        bad("[tcp]\naddress = \"0.0.0.0\"", "not a valid IP:port");
        bad(
            "[udp]\nenabled = false\n[tcp]\nenabled = false",
            "nothing to do",
        );
        bad("[server]\nmax_message_size = 100", "max_message_size");
        bad("[server]\nqueue_size = 0", "queue_size");
        bad("[tcp]\nmax_connections = 0", "max_connections");
        bad(
            "[rate_limit]\nmessages_per_second = 0",
            "messages_per_second",
        );
        bad(
            "[rate_limit]\nmessages_per_second = -5",
            "messages_per_second",
        );
        bad(
            "[rate_limit]\nmessages_per_second = 5\nburst = 0.5",
            "burst",
        );
        bad("[rate_limit]\nburst = 5", "messages_per_second");
        bad(
            "[[rule]]\nfacility = \"nope\"\noutputs = [{type=\"stdout\"}]",
            "unknown facility",
        );
        bad(
            "[[rule]]\nfacility = []\noutputs = [{type=\"stdout\"}]",
            "facility list is empty",
        );
        bad(
            "[[rule]]\nseverity = \"loud\"\noutputs = [{type=\"stdout\"}]",
            "unknown severity",
        );
        bad(
            "[[rule]]\nhostname = \"(\"\noutputs = [{type=\"stdout\"}]",
            "invalid hostname regex",
        );
        bad("[[rule]]\noutputs = []", "at least one output");
        bad("[[rule]]\nseverity = \"err\"", "missing field `outputs`");
        bad("[[rule]]\noutputs = [{type=\"syslog\"}]", "unknown variant");
        bad(
            "[[rule]]\noutputs = [{type=\"file\"}]",
            "missing field `path`",
        );
        bad(
            "[[rule]]\noutputs = [{type=\"file\", path=\"\"}]",
            "empty path",
        );
        bad(
            "[[rule]]\noutputs = [{type=\"file\", path=\"/a\", format=\"xml\"}]",
            "unknown variant",
        );
        bad(
            "[[rule]]\noutputs = [{type=\"stdout\", path=\"/a\"}]",
            "unknown field",
        );
        bad(
            "[[rule]]\noutputs = [{type=\"file\", path=\"/a\", format=\"text\"}]\n[default]\noutputs = [{type=\"file\", path=\"/a\"}]",
            "both jsonl and text",
        );
        bad("[default]\noutputs = []", "at least one output");
        bad("this is not toml", "invalid TOML");
    }

    #[test]
    fn facility_aliases_and_case() {
        let c = Config::from_toml(
            "[[rule]]\nfacility = [\"AUTH\", \"local7\", \"audit\"]\nseverity = \"Warn\"\noutputs = [{type=\"stdout\"}]",
        )
        .unwrap();
        let names: Vec<_> = c.rules[0]
            .facilities
            .as_ref()
            .unwrap()
            .iter()
            .map(|f| f.name())
            .collect();
        assert_eq!(names, ["auth", "local7", "security"]);
    }
}
