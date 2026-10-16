//! Rule evaluation and dispatch to outputs.
//!
//! Rules are evaluated in file order. Every matching rule's outputs receive
//! the message (fan-out) unless a matching rule has `stop = true`, which ends
//! evaluation. A message that matched no rule goes to the default outputs.
//! A message is written at most once per output even when several matching
//! rules share it.

use std::collections::HashMap;

use crate::config::{Config, OutputSpec, Rule};
use crate::message::Message;
use crate::output::Sink;

pub struct Router {
    rules: Vec<CompiledRule>,
    default: Vec<usize>,
    sinks: Vec<Sink>,
    hit: Vec<bool>,
    scratch: Vec<u8>,
}

struct CompiledRule {
    rule: Rule,
    outputs: Vec<usize>,
}

impl Router {
    /// Opens every output. Fails if any cannot be opened, so a broken output
    /// is reported at startup (and by `-t`) rather than at the first message.
    pub fn new(config: Config) -> Result<Router, String> {
        let mut index: HashMap<OutputSpec, usize> = HashMap::new();
        let mut sinks = Vec::new();
        let mut resolve = |spec: &OutputSpec| -> Result<usize, String> {
            if let Some(&i) = index.get(spec) {
                return Ok(i);
            }
            let sink = Sink::open(spec).map_err(|e| match spec {
                OutputSpec::File { path, .. } => {
                    format!("cannot open output {}: {e}", path.display())
                }
                OutputSpec::Stdout { .. } => format!("cannot open stdout: {e}"),
            })?;
            sinks.push(sink);
            index.insert(spec.clone(), sinks.len() - 1);
            Ok(sinks.len() - 1)
        };

        let mut rules = Vec::with_capacity(config.rules.len());
        for rule in config.rules {
            let outputs = rule
                .outputs
                .iter()
                .map(&mut resolve)
                .collect::<Result<_, _>>()?;
            rules.push(CompiledRule { rule, outputs });
        }
        let default = config
            .default_outputs
            .iter()
            .map(&mut resolve)
            .collect::<Result<_, _>>()?;

        let n = sinks.len();
        Ok(Router {
            rules,
            default,
            sinks,
            hit: vec![false; n],
            scratch: Vec::with_capacity(4096),
        })
    }

    pub fn describe_outputs(&self) -> Vec<String> {
        self.sinks.iter().map(Sink::describe).collect()
    }

    /// Indices of the outputs `msg` should be written to.
    pub fn route(&mut self, msg: &Message) -> Vec<usize> {
        self.hit.iter_mut().for_each(|h| *h = false);
        let mut matched = false;
        for cr in &self.rules {
            if rule_matches(&cr.rule, msg) {
                matched = true;
                for &o in &cr.outputs {
                    self.hit[o] = true;
                }
                if cr.rule.stop {
                    break;
                }
            }
        }
        if !matched {
            for &o in &self.default {
                self.hit[o] = true;
            }
        }
        (0..self.hit.len()).filter(|&i| self.hit[i]).collect()
    }

    pub fn dispatch(&mut self, msg: &Message) {
        for i in self.route(msg) {
            self.sinks[i].write(msg, &mut self.scratch);
        }
    }

    pub fn flush(&mut self) {
        self.sinks.iter_mut().for_each(Sink::flush);
    }

    pub fn reopen(&mut self) {
        self.sinks.iter_mut().for_each(Sink::reopen);
    }
}

/// All configured criteria must match. The hostname regex is matched against
/// the message's HOSTNAME, or the source IP when the message carries none.
/// An appname criterion never matches a message without an APP-NAME.
pub fn rule_matches(rule: &Rule, msg: &Message) -> bool {
    if let Some(fs) = &rule.facilities {
        if !fs.contains(&msg.facility) {
            return false;
        }
    }
    if let Some(sev) = rule.severity {
        if !sev.matches(msg.severity) {
            return false;
        }
    }
    if let Some(re) = &rule.hostname {
        let matched = match &msg.hostname {
            Some(h) => re.is_match(h),
            None => re.is_match(&msg.source.ip().to_string()),
        };
        if !matched {
            return false;
        }
    }
    if let Some(re) = &rule.appname {
        match &msg.appname {
            Some(a) if re.is_match(a) => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Transport;
    use crate::parse::{parse, Context};
    use crate::time::Timestamp;

    fn router(rules_toml: &str) -> Router {
        let cfg = Config::from_toml(&format!(
            "{rules_toml}\n[default]\noutputs = [{{type = \"stdout\", format = \"jsonl\"}}]"
        ))
        .unwrap();
        Router::new(cfg).unwrap()
    }

    fn msg(raw: &str) -> Message {
        parse(
            raw.as_bytes(),
            Context {
                received_at: Timestamp::now(),
                source: "10.1.2.3:514".parse().unwrap(),
                transport: Transport::Udp,
                truncated: false,
            },
        )
    }

    // Outputs are numbered in order of first appearance: rule outputs first,
    // then the default (stdout jsonl) last.
    #[test]
    fn routing() {
        let mut r = router(
            r#"
            [[rule]]
            name = "auth"
            facility = ["auth", "authpriv"]
            outputs = [{ type = "stdout", format = "text" }]

            [[rule]]
            name = "errors"
            severity = "err"
            outputs = [{ type = "stdout", format = "text" }]

            [[rule]]
            name = "web-nginx"
            hostname = '^web\d+$'
            appname = "^nginx$"
            stop = true
            outputs = [{ type = "stdout", format = "text" }]

            [[rule]]
            name = "never-after-stop"
            hostname = '^web\d+$'
            outputs = [{ type = "file", path = "/dev/null", format = "text" }]

            [[rule]]
            name = "exact-debug"
            severity = "=debug"
            outputs = [{ type = "file", path = "/dev/null", format = "text" }]
            "#,
        );
        assert_eq!(r.sinks.len(), 3);

        // auth.info matches rule 1 only.
        assert_eq!(r.route(&msg("<38>Oct 16 10:00:00 db1 sshd: x")), vec![0]);
        // auth.err matches rules 1 and 2, both stdout-text: written once.
        assert_eq!(r.route(&msg("<35>Oct 16 10:00:00 db1 sshd: x")), vec![0]);
        // user.notice from web1/nginx: stop rule wins, later rule skipped.
        assert_eq!(r.route(&msg("<13>Oct 16 10:00:00 web1 nginx: x")), vec![0]);
        // web1 but other app: rule 4.
        assert_eq!(r.route(&msg("<13>Oct 16 10:00:00 web1 cron: x")), vec![1]);
        // user.debug: exact-debug.
        assert_eq!(r.route(&msg("<15>Oct 16 10:00:00 db1 app: x")), vec![1]);
        // user.info: nothing matches, default.
        assert_eq!(r.route(&msg("<14>Oct 16 10:00:00 db1 app: x")), vec![2]);
    }

    #[test]
    fn hostname_falls_back_to_source_ip() {
        let mut r = router(
            r#"
            [[rule]]
            hostname = '^10\.1\.'
            outputs = [{ type = "stdout", format = "text" }]
            "#,
        );
        assert_eq!(r.route(&msg("garbage without pri")), vec![0]);
        assert_eq!(r.route(&msg("<13>Oct 16 10:00:00 other app: x")), vec![1]);
    }

    #[test]
    fn appname_rule_does_not_match_missing_appname() {
        let mut r = router(
            r#"
            [[rule]]
            appname = ".*"
            outputs = [{ type = "stdout", format = "text" }]
            "#,
        );
        assert_eq!(r.route(&msg("<13>1 - - - - - - x")), vec![1]);
        assert_eq!(r.route(&msg("<13>1 - - app - - - x")), vec![0]);
    }

    #[test]
    fn unopenable_output_fails() {
        let cfg = Config::from_toml(
            "[default]\noutputs = [{type = \"file\", path = \"/proc/definitely/not/here.log\"}]",
        )
        .unwrap();
        let err = Router::new(cfg).err().unwrap();
        assert!(err.contains("cannot open output"), "{err}");
    }
}
