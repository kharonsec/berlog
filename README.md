# berlog

A minimal, modern syslog daemon in Rust. berlog listens for syslog over UDP
and TCP, parses RFC 3164 and RFC 5424 messages, routes them by facility,
severity, hostname and app name, and writes them to JSONL files, plain-text
files or stdout.

## Why

Rust has syslog *parsers* and *client* libraries, but no syslog *server*:
the daemons people actually run are rsyslog (C, 25 years old) and syslog-ng
(C/C++). berlog is a small, auditable collector you can `cargo install` and
put in front of Wazuh or any other SIEM. It has no `unsafe` code, a short
dependency list, and parsers that turn hostile input into marked records
instead of crashes or dropped messages.

It is deliberately small. TLS, RELP, forwarding, disk queues, databases and
pattern matching are out of scope for now.

## Quick start

```sh
cargo install --path .

cat > berlog.toml <<'EOF'
[udp]
address = "127.0.0.1:5514"
[tcp]
address = "127.0.0.1:5514"
[default]
outputs = [
  { type = "file", path = "./logs/messages.jsonl" },
  { type = "stdout", format = "text" },
]
EOF

berlog -t -c berlog.toml      # check the config
berlog -c berlog.toml         # run it
```

From another terminal:

```sh
logger -n 127.0.0.1 -P 5514 -d -p auth.warning -t sshd "hello over UDP"
logger -n 127.0.0.1 -P 5514 -T --octet-count -t app "hello over TCP"
tail -f logs/messages.jsonl
```

### Docker

```sh
docker build -t berlog .
docker run --rm -p 514:5514/udp -p 514:5514/tcp -v berlog-logs:/var/log/berlog berlog
```

The image is distroless, runs as a non-root user (uid 65532), and keeps logs
in the `/var/log/berlog` volume. The image's config (`docker/berlog.toml`)
listens on 5514 and writes everything to `/var/log/berlog/messages.jsonl`.
To use your own config, mount it over `/etc/berlog/berlog.toml`.

## Command line

```text
berlog [-c CONFIG] [-t]

  -c, --config PATH   configuration file (default: /etc/berlog/berlog.toml)
  -t, --test          check the configuration and open all outputs, then exit
  -V, --version       print version and exit
  -h, --help          print help and exit
```

| Exit code | Meaning |
|-----------|---------|
| 0 | clean shutdown, or `-t` succeeded |
| 1 | configuration error, output cannot be opened, port cannot be bound |
| 2 | usage error |

**Signals.** SIGTERM and SIGINT start a graceful shutdown. Listeners stop,
TCP data the kernel has already received is still read, queued messages are
written, and outputs are flushed. A second SIGTERM/SIGINT exits immediately.
SIGHUP reopens output files, for logrotate:

```text
/var/log/berlog/*.log /var/log/berlog/*.jsonl {
    daily
    rotate 14
    compress
    delaycompress
    postrotate
        pkill -HUP -x berlog
    endscript
}
```

**Diagnostics.** berlog writes its own logs to stderr. Set the level with
`BERLOG_LOG=error|warn|info|debug` (default `info`).

## Configuration reference

The config is TOML. **Every section and key is optional.** Unknown keys,
unknown facility or severity names, invalid regexes and invalid addresses are
errors. berlog refuses to start rather than run half-configured. An empty
file gives you UDP and TCP on `0.0.0.0:5514`, writing everything to
`/var/log/berlog/messages.jsonl`.

A fully commented example is in [`berlog.example.toml`](berlog.example.toml).

### `[server]`

| Key | Default | Description |
|-----|---------|-------------|
| `max_message_size` | `65536` | Largest payload in bytes (480 … 16777216). Longer UDP datagrams and TCP frames are cut to this size and marked `truncated`. |
| `queue_size` | `10000` | Messages buffered between listeners and the writer. |

### `[udp]`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | |
| `address` | `"0.0.0.0:5514"` | `IP:port`. IPv6: `"[::]:5514"`. Port `0` picks a free port. |

### `[tcp]`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | |
| `address` | `"0.0.0.0:5514"` | `IP:port`. |
| `max_connections` | `256` | Connections beyond this are accepted and closed immediately. |
| `idle_timeout_secs` | `300` | Close a connection that sends nothing for this many seconds; any partially received frame is discarded. `0` disables the timeout. |

At least one of UDP and TCP must be enabled.

### `[rate_limit]`

Per-source-IP token bucket. Leave the section out to disable rate limiting
(the default).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Lets you keep the section but turn it off. |
| `messages_per_second` | *(required)* | Refill rate. |
| `burst` | `messages_per_second` | Bucket size, at least 1. |

Messages over the limit are dropped. berlog logs one warning when a source
starts being limited, and one more with the drop count when the source is
under the limit again.

### `[[rule]]`

Rules are evaluated in file order. A message is written to the outputs of
**every** rule it matches (each output at most once), unless a matching rule
has `stop = true`, which ends evaluation. A message that matches no rule goes
to `[default]`.

| Key | Description |
|-----|-------------|
| `name` | Label for error messages. Defaults to `rule-N`. |
| `facility` | A name or a list: `"auth"`, `["auth", "authpriv"]`. |
| `severity` | `"warning"` matches warning **and more severe** (emerg … warning). `"=warning"` matches exactly warning. |
| `hostname` | Regex, matched against HOSTNAME, or against the source IP when the message has no hostname. |
| `appname` | Regex, matched against APP-NAME (the RFC 3164 TAG). Never matches a message without one. |
| `stop` | `true` to stop evaluating later rules when this one matches. |
| `outputs` | *(required)* List of outputs, see below. |

All given criteria must match. A rule with no criteria matches everything.
Regexes use the [`regex`](https://docs.rs/regex) crate syntax and are
unanchored, so add `^…$` for an exact match. In TOML, single-quoted strings
avoid double escaping: `hostname = '^web\d+$'`.

Facility names: `kern user mail daemon auth syslog lpr news uucp cron
authpriv ftp ntp security console solaris-cron local0 … local7` (aliases:
`audit`, `alert`, `clock`).
Severity names: `emerg alert crit err warning notice info debug` (aliases:
`panic`, `critical`, `error`, `warn`).

### `[default]`

| Key | Default | Description |
|-----|---------|-------------|
| `outputs` | `[{ type = "file", path = "/var/log/berlog/messages.jsonl" }]` | Where unmatched messages go. |

### Outputs

```toml
{ type = "file",   path = "/var/log/berlog/auth.log", format = "text" }
{ type = "file",   path = "/var/log/berlog/all.jsonl" }               # format defaults to jsonl
{ type = "stdout", format = "jsonl" }                                 # format defaults to text
```

Files are opened in append mode with permissions `0640`, and missing parent
directories are created. All outputs are opened at startup, and with `-t`,
so permission problems show up immediately. One file can't be used with two
formats.

### Example

```toml
[rate_limit]
messages_per_second = 500
burst = 2000

[[rule]]
name = "auth"
facility = ["auth", "authpriv"]
outputs = [{ type = "file", path = "/var/log/berlog/auth.log", format = "text" }]

[[rule]]
name = "page-someone"
severity = "crit"
outputs = [{ type = "stdout", format = "jsonl" }]

[[rule]]
name = "drop-chatty-lb-into-its-own-file"
hostname = '^lb\d+\.'
stop = true
outputs = [{ type = "file", path = "/var/log/berlog/lb.jsonl" }]

[default]
outputs = [{ type = "file", path = "/var/log/berlog/messages.jsonl" }]
```

## Output formats

### JSONL

One object per line. The schema is stable: every key is always present, and
missing values are `null`.

```json
{"timestamp":"2003-10-11T22:14:15.003000Z","received_at":"2026-10-16T14:45:48.092934Z","facility":"local4","severity":"notice","hostname":"mymachine.example.com","appname":"evntslog","procid":null,"msgid":"ID47","structured_data":{"exampleSDID@32473":{"iut":"3","eventSource":"Application","eventID":"1011"}},"message":"An application event log entry...","source":"192.0.2.10:51544","transport":"tcp","parse_status":"rfc5424","parse_error":null,"truncated":false}
```

| Field | Notes |
|-------|-------|
| `timestamp` | Event time from the header, in UTC with microseconds. Falls back to `received_at` if the header has none. |
| `received_at` | When berlog received the message. |
| `structured_data` | `{SD-ID: {PARAM: value}}`. A PARAM name that repeats becomes an array. |
| `source` | Peer `IP:port`. |
| `parse_status` | `rfc5424`, `rfc3164` or `unparsed`. |
| `parse_error` | Why parsing failed, when `unparsed`. |
| `truncated` | The payload hit `max_message_size`, or the TCP stream ended mid-frame. |

### Text

```text
2026-10-16T10:00:00.000000Z bastion auth.warning sshd[77]: Failed password for root
```

`TIMESTAMP HOST FACILITY.SEVERITY [TAG[PID]:] MESSAGE`. HOST is the source IP
when the message has no hostname. Control characters, including newlines and
NULs, are written as `#ooo` octal escapes (as rsyslog does), so one message
is always one line and can't forge entries.

## Parsing behavior

berlog never drops a message because it can't parse it.

- **No valid `<PRI>`** (missing, non-numeric, more than 191, …): the record is
  `unparsed`, the whole payload is kept as `message`, and facility/severity
  default to `user.notice` (RFC 3164 §4.3.3).
- **`<PRI>` followed by `VERSION SP`**: RFC 5424, parsed strictly. That means
  field length limits, a valid RFC 3339 timestamp and well-formed structured
  data with `\"`, `\\`, `\]` escapes. A leading BOM on MSG is removed. If the
  header is malformed, the record is `unparsed` but keeps the PRI.
- **Anything else after `<PRI>`**: RFC 3164, best effort.
  - `Mmm dd hh:mm:ss` timestamps have no year. berlog picks the last, current
    or next year, whichever puts the timestamp closest to the receive time.
    So a `Dec 31` message received on Jan 1 lands in the right year.
  - They have no time zone either, and are read as **UTC**. Senders that
    log local time should switch to RFC 5424 or RFC 3339 timestamps, which
    are also accepted in this position.
  - `HOSTNAME` is the first word unless it looks like a tag (`app:` or
    `app[pid]`). `TAG[PID]:` becomes `appname`/`procid`.
- Invalid UTF-8 is replaced with U+FFFD. NUL bytes are kept. Trailing
  CR/LF/NUL are trimmed.

### TCP framing (RFC 6587)

Both octet counting (`LEN SP MSG`) and LF-delimited framing are supported.
The first frame on a connection decides which one is used, and that choice
then sticks, so an LF-framed message starting with `2026 …` is never misread
as a length. If an octet-counting connection sends something that isn't a
valid length header, berlog reads that one frame as a line. Frames over
`max_message_size` are truncated, and the rest of the frame is skipped
without being buffered. A connection that closes mid-frame still delivers
what it sent, marked `truncated`.

## Architecture

```text
src/
  main.rs          CLI, -t, signal handlers, startup banner
  daemon.rs        listener threads, writer thread, shutdown orchestration
  framing.rs       RFC 6587 TCP framer (pure state machine, no I/O)
  parse/           rfc5424.rs, rfc3164.rs, PRI and dispatch in mod.rs
  message.rs       normalized Message, Facility, Severity
  config.rs        TOML schema, defaults, validation
  router.rs        rule matching and fan-out
  output.rs        JSONL/text formatting, file and stdout sinks
  ratelimit.rs     per-source token bucket
  time.rs          UTC timestamps and RFC 3339 (no date crate)
  diag.rs          stderr diagnostics
```

berlog uses plain threads, not an async runtime. One thread receives UDP. One
thread accepts TCP and starts one thread per connection, up to
`max_connections`. Listener threads parse and rate-limit, then send messages
over a bounded channel to a single writer thread. The writer owns all outputs,
so they need no locks and each file stays in order. It flushes whenever the
queue drains.

When the queue is full, a TCP connection blocks, which pushes back on the
sender through TCP. UDP has no way to push back, so it drops and counts the
message. The counts are logged at shutdown.

## Development and testing

```sh
cargo test                                  # unit, integration, CLI and fuzz tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

- **Unit tests** cover the RFC 5424 §6.5 and RFC 3164 §5.4 example messages,
  year inference, structured-data escaping, and adversarial input: empty
  payloads, payloads over 8 KiB, invalid PRI, embedded NULs, invalid UTF-8,
  and every prefix of valid messages. The TCP framer tests run every input
  in one piece, byte by byte, and split at every possible point.
- **Integration tests** (`tests/daemon.rs`) start the real binary on
  ephemeral `127.0.0.1` ports and send UDP and TCP traffic in both framings
  with deliberately split writes. They then check the output files, including
  truncation, mid-frame disconnects, rate limiting, SIGTERM draining, SIGHUP
  reopening and the connection cap. If util-linux `logger` is installed, they
  also test against it.
- **Fuzz tests** (`tests/fuzz.rs`) push random bytes, mutated valid messages
  and random streams through the framer, both parsers and both output
  formats. They check that nothing panics, the JSON is valid and text output
  is one line per message. The runs are deterministic. For longer runs:

  ```sh
  BERLOG_FUZZ_ITERS=1000000 BERLOG_FUZZ_SEED=42 cargo test --release --test fuzz
  ```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
