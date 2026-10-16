use super::*;
use crate::time::Timestamp;

fn ctx_at(received: &str) -> Context {
    Context {
        received_at: Timestamp::parse_rfc3339(received).unwrap(),
        source: "192.0.2.10:514".parse().unwrap(),
        transport: Transport::Udp,
        truncated: false,
    }
}

fn ctx() -> Context {
    ctx_at("2026-10-16T12:00:00Z")
}

fn p(s: &str) -> Message {
    parse(s.as_bytes(), ctx())
}

fn sd(id: &str, params: &[(&str, &str)]) -> SdElement {
    SdElement {
        id: id.into(),
        params: params
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    }
}

fn assert_unparsed(m: &Message) {
    assert!(
        matches!(m.parse_status, ParseStatus::Unparsed { .. }),
        "expected unparsed, got {:?}",
        m.parse_status
    );
}

// ---------------------------------------------------------------- PRI

#[test]
fn pri_decoding() {
    let m = p("<0>1 - - - - - -");
    assert_eq!((m.facility, m.severity), (Facility::KERN, Severity::EMERG));
    let m = p("<191>1 - - - - - -");
    assert_eq!(m.facility.name(), "local7");
    assert_eq!(m.severity, Severity::DEBUG);
    let m = p("<13>hello");
    assert_eq!((m.facility, m.severity), (Facility::USER, Severity::NOTICE));
    // Leading zeros are tolerated.
    let m = p("<013>hello");
    assert_eq!(m.parse_status, ParseStatus::Rfc3164);
    assert_eq!(m.severity, Severity::NOTICE);
}

#[test]
fn invalid_pri_is_unparsed_with_defaults() {
    for bad in [
        "<192>1 - - - - - -",
        "<1000>x",
        "<-1>x",
        "<>x",
        "<abc>x",
        "<13",
        "<",
        "13>x",
        "no pri at all",
        "<0013>x",
    ] {
        let m = p(bad);
        assert_unparsed(&m);
        assert_eq!(m.message, bad, "raw payload must be preserved");
        assert_eq!((m.facility, m.severity), (Facility::USER, Severity::NOTICE));
        assert_eq!(m.timestamp, m.received_at);
    }
}

// ---------------------------------------------------------------- RFC 5424

#[test]
fn rfc5424_example_1() {
    // RFC 5424 section 6.5, example 1 (BOM included as on the wire).
    let raw = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \u{FEFF}'su root' failed for lonvick on /dev/pts/8";
    let m = p(raw);
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    assert_eq!(m.facility, Facility::AUTH);
    assert_eq!(m.severity.name(), "crit");
    assert_eq!(m.timestamp.to_string(), "2003-10-11T22:14:15.003000Z");
    assert_eq!(m.hostname.as_deref(), Some("mymachine.example.com"));
    assert_eq!(m.appname.as_deref(), Some("su"));
    assert_eq!(m.procid, None);
    assert_eq!(m.msgid.as_deref(), Some("ID47"));
    assert!(m.structured_data.is_empty());
    assert_eq!(m.message, "'su root' failed for lonvick on /dev/pts/8");
}

#[test]
fn rfc5424_example_2() {
    let m = p("<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.");
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    assert_eq!(m.facility, Facility::LOCAL4);
    assert_eq!(m.severity, Severity::NOTICE);
    assert_eq!(m.timestamp.to_string(), "2003-08-24T12:14:15.000003Z");
    assert_eq!(m.hostname.as_deref(), Some("192.0.2.1"));
    assert_eq!(m.appname.as_deref(), Some("myproc"));
    assert_eq!(m.procid.as_deref(), Some("8710"));
    assert_eq!(m.msgid, None);
    assert_eq!(m.message, "%% It's time to make the do-nuts.");
}

#[test]
fn rfc5424_example_3() {
    let m = p("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] \u{FEFF}An application event log entry...");
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    assert_eq!(m.appname.as_deref(), Some("evntslog"));
    assert_eq!(
        m.structured_data,
        vec![sd(
            "exampleSDID@32473",
            &[
                ("iut", "3"),
                ("eventSource", "Application"),
                ("eventID", "1011")
            ]
        )]
    );
    assert_eq!(m.message, "An application event log entry...");
}

#[test]
fn rfc5424_example_4_multiple_sd_no_msg() {
    let m = p("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]");
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    assert_eq!(m.structured_data.len(), 2);
    assert_eq!(
        m.structured_data[1],
        sd("examplePriority@32473", &[("class", "high")])
    );
    assert_eq!(m.message, "");
}

#[test]
fn rfc5424_all_nil() {
    let m = p("<14>1 - - - - - -");
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    assert_eq!(m.timestamp, m.received_at);
    assert_eq!(m.hostname, None);
    assert_eq!(m.appname, None);
    assert_eq!(m.message, "");
}

#[test]
fn rfc5424_sd_escapes() {
    let m = p(r#"<14>1 - h a - - [x@1 a="q\"uote" b="back\\slash" c="br\]acket" d="keep\n"] m"#);
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    assert_eq!(
        m.structured_data[0].params,
        vec![
            ("a".into(), "q\"uote".into()),
            ("b".into(), "back\\slash".into()),
            ("c".into(), "br]acket".into()),
            ("d".into(), "keep\\n".into()),
        ]
    );
    assert_eq!(m.message, "m");
}

#[test]
fn rfc5424_sd_value_may_contain_spaces_and_utf8() {
    let m = p("<14>1 - h a - - [x@1 msg=\"héllo wörld [ok\"] rest");
    assert_eq!(m.structured_data[0].params[0].1, "héllo wörld [ok");
    assert_eq!(m.message, "rest");
}

#[test]
fn rfc5424_malformed_falls_back_to_unparsed_keeping_pri() {
    for bad in [
        "<34>1 not-a-time host app - - - msg",
        "<34>2 - - - - - - msg",         // unsupported version
        "<34>1 - - - - -",               // missing SD
        "<34>1 - - - - - [unterminated", // unterminated SD
        "<34>1 - - - - - [id a=\"x]",    // unterminated value
        "<34>1 - - - - - [id a=x]",      // unquoted value
        "<34>1 - - - - - [id a]",        // missing '='
        "<34>1 - - - - - []",            // empty SD-ID
        "<34>1 - - - - - -msg",          // no SP after SD
        "<34>1 - - - - - [a][b]x",       // junk after SD
        "<34>1 - - - - ThisMsgIdIsWayTooLongForTheRfc5424Limit -", // MSGID > 32
        "<34>1  - - - - -",              // empty TIMESTAMP field
    ] {
        let m = p(bad);
        assert_unparsed(&m);
        assert_eq!(m.facility, Facility::AUTH, "{bad}");
        assert_eq!(m.severity.name(), "crit", "{bad}");
        assert_eq!(m.message, bad);
    }
}

#[test]
fn rfc5424_field_length_limits() {
    let host = "h".repeat(255);
    let m = p(&format!("<14>1 - {host} - - - -"));
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    let m = p(&format!("<14>1 - {host}x - - - -"));
    assert_unparsed(&m);
    let app = "a".repeat(49);
    assert_unparsed(&p(&format!("<14>1 - - {app} - - -")));
    let sdid = "s".repeat(33);
    assert_unparsed(&p(&format!("<14>1 - - - - - [{sdid}]")));
}

// ---------------------------------------------------------------- RFC 3164

#[test]
fn rfc3164_example_1() {
    // RFC 3164 section 5.4, example 1.
    let m = parse(
        b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
        ctx_at("2003-10-12T00:00:00Z"),
    );
    assert_eq!(m.parse_status, ParseStatus::Rfc3164);
    assert_eq!(m.facility, Facility::AUTH);
    assert_eq!(m.severity.name(), "crit");
    assert_eq!(m.timestamp.to_string(), "2003-10-11T22:14:15.000000Z");
    assert_eq!(m.hostname.as_deref(), Some("mymachine"));
    assert_eq!(m.appname.as_deref(), Some("su"));
    assert_eq!(m.procid, None);
    assert_eq!(m.message, "'su root' failed for lonvick on /dev/pts/8");
}

#[test]
fn rfc3164_example_2_no_tag() {
    let m = parse(
        b"<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!",
        ctx_at("2003-02-05T18:00:00Z"),
    );
    assert_eq!(m.parse_status, ParseStatus::Rfc3164);
    assert_eq!(m.timestamp.to_string(), "2003-02-05T17:32:18.000000Z");
    assert_eq!(m.hostname.as_deref(), Some("10.0.0.99"));
    assert_eq!(m.appname, None);
    assert_eq!(m.message, "Use the BFG!");
}

#[test]
fn rfc3164_example_3_misplaced_year() {
    // The RFC uses this to show a relay's view of a malformed header: "CST"
    // lands in HOSTNAME and the rest is content.
    let m = parse(
        b"<165>Aug 24 05:34:00 CST 1987 mymachine myproc[10]: %% It's time to make the do-nuts.  %%",
        ctx_at("1987-08-24T12:00:00Z"),
    );
    assert_eq!(m.parse_status, ParseStatus::Rfc3164);
    assert_eq!(m.facility, Facility::LOCAL4);
    assert_eq!(m.hostname.as_deref(), Some("CST"));
    assert_eq!(m.appname, None);
    assert!(m.message.starts_with("1987 mymachine myproc[10]: %%"));
}

#[test]
fn rfc3164_example_4_no_valid_timestamp() {
    let m = p("<0>1990 Oct 22 10:52:01 TZ-6 scapegoat.dmz.example.org 10.1.2.3 sched[0]: That's All Folks!");
    assert_eq!(m.parse_status, ParseStatus::Rfc3164);
    assert_eq!((m.facility, m.severity), (Facility::KERN, Severity::EMERG));
    assert_eq!(m.timestamp, m.received_at);
    assert_eq!(m.hostname, None);
    assert_eq!(
        m.message,
        "1990 Oct 22 10:52:01 TZ-6 scapegoat.dmz.example.org 10.1.2.3 sched[0]: That's All Folks!"
    );
}

#[test]
fn rfc3164_tag_with_pid() {
    let m = p("<86>Oct 16 11:59:58 web01 sshd[4242]: Accepted publickey for root");
    assert_eq!(m.hostname.as_deref(), Some("web01"));
    assert_eq!(m.appname.as_deref(), Some("sshd"));
    assert_eq!(m.procid.as_deref(), Some("4242"));
    assert_eq!(m.message, "Accepted publickey for root");
    assert_eq!(m.facility.name(), "authpriv");
    assert_eq!(m.severity, Severity::INFO);
}

#[test]
fn rfc3164_without_hostname() {
    // What local senders often emit: no HOSTNAME, straight to TAG.
    let m = p("<13>Oct 16 11:59:58 myapp[7]: hi");
    assert_eq!(m.hostname, None);
    assert_eq!(m.appname.as_deref(), Some("myapp"));
    assert_eq!(m.procid.as_deref(), Some("7"));
    assert_eq!(m.message, "hi");
    let m = p("<13>Oct 16 11:59:58 myapp: hi");
    assert_eq!(m.hostname, None);
    assert_eq!(m.appname.as_deref(), Some("myapp"));
}

#[test]
fn rfc3164_no_timestamp_still_finds_tag() {
    let m = p("<13>cron[99]: job done");
    assert_eq!(m.parse_status, ParseStatus::Rfc3164);
    assert_eq!(m.appname.as_deref(), Some("cron"));
    assert_eq!(m.procid.as_deref(), Some("99"));
    assert_eq!(m.message, "job done");
}

#[test]
fn rfc3164_rfc3339_timestamp_variant() {
    let m = p("<13>2026-10-16T11:59:58.123+02:00 host app: x");
    assert_eq!(m.timestamp.to_string(), "2026-10-16T09:59:58.123000Z");
    assert_eq!(m.hostname.as_deref(), Some("host"));
    assert_eq!(m.appname.as_deref(), Some("app"));
}

#[test]
fn rfc3164_unpadded_day_and_fraction() {
    let m = p("<13>Oct 6 01:02:03.250 host app: x");
    assert_eq!(m.timestamp.to_string(), "2026-10-06T01:02:03.250000Z");
    assert_eq!(m.hostname.as_deref(), Some("host"));
}

#[test]
fn rfc3164_year_gap_december_received_in_january() {
    let m = parse(
        b"<13>Dec 31 23:59:00 h a: x",
        ctx_at("2026-01-01T00:00:30Z"),
    );
    assert_eq!(m.timestamp.to_string(), "2025-12-31T23:59:00.000000Z");
}

#[test]
fn rfc3164_year_gap_sender_clock_ahead_across_new_year() {
    let m = parse(
        b"<13>Jan  1 00:00:05 h a: x",
        ctx_at("2025-12-31T23:59:59Z"),
    );
    assert_eq!(m.timestamp.to_string(), "2026-01-01T00:00:05.000000Z");
}

#[test]
fn rfc3164_year_gap_feb_29() {
    // Received just after a leap day in a non-leap year: only the previous
    // leap year produces a valid date.
    let m = parse(
        b"<13>Feb 29 10:00:00 h a: x",
        ctx_at("2025-03-01T00:00:00Z"),
    );
    assert_eq!(m.timestamp.to_string(), "2024-02-29T10:00:00.000000Z");
}

#[test]
fn rfc3164_invalid_dates_treated_as_content() {
    for raw in [
        "<13>Feb 30 10:00:00 h a: x",
        "<13>Foo 10 10:00:00 h a: x",
        "<13>Oct 10 25:00:00 h a: x",
        "<13>Oct 10 10:00 h a: x",
        "<13>Oct 10 10:00:00x h a: x",
    ] {
        let m = p(raw);
        assert_eq!(m.parse_status, ParseStatus::Rfc3164, "{raw}");
        assert_eq!(m.timestamp, m.received_at, "{raw}");
        assert_eq!(m.hostname, None, "{raw}");
        assert_eq!(m.message, &raw[4..], "{raw}");
    }
}

// ---------------------------------------------------------------- adversarial

#[test]
fn empty_payload() {
    let m = p("");
    assert_unparsed(&m);
    assert_eq!(m.message, "");
    // Only trailer bytes.
    assert_unparsed(&parse(b"\r\n\0\n", ctx()));
}

#[test]
fn trailing_newlines_and_nuls_are_trimmed() {
    let m = parse(b"<13>Oct 16 11:59:58 h app: msg\r\n\0", ctx());
    assert_eq!(m.message, "msg");
}

#[test]
fn embedded_nul_bytes_are_preserved() {
    let m = parse(b"<13>Oct 16 11:59:58 h app: a\0b", ctx());
    assert_eq!(m.parse_status, ParseStatus::Rfc3164);
    assert_eq!(m.message, "a\0b");
    let m = parse(b"<13>1 - h app - - - a\0b", ctx());
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    assert_eq!(m.message, "a\0b");
    let m = parse(b"\0\0\0<13>x", ctx());
    assert_unparsed(&m);
}

#[test]
fn invalid_utf8_is_replaced_not_rejected() {
    let m = parse(b"<13>1 - h app - - - \xff\xfe ok", ctx());
    assert_eq!(m.parse_status, ParseStatus::Rfc5424);
    assert_eq!(m.message, "\u{FFFD}\u{FFFD} ok");
    let m = parse(b"<13>Oct 16 11:59:58 h\xff app: x", ctx());
    assert_eq!(m.parse_status, ParseStatus::Rfc3164);
    let m = parse(b"\xff\xff", ctx());
    assert_unparsed(&m);
}

#[test]
fn large_payloads() {
    let big = "A".repeat(9000);
    let m = p(&format!("<13>Oct 16 11:59:58 h app: {big}"));
    assert_eq!(m.message.len(), 9000);
    let m = p(&format!("<13>1 - h app - - - {big}"));
    assert_eq!(m.message.len(), 9000);
    let m = p(&big);
    assert_unparsed(&m);
    assert_eq!(m.message.len(), 9000);
    // A gigantic SD value.
    let m = p(&format!("<13>1 - h app - - [x@1 v=\"{big}\"]"));
    assert_eq!(m.structured_data[0].params[0].1.len(), 9000);
}

#[test]
fn truncation_flag_propagates() {
    let mut c = ctx();
    c.truncated = true;
    assert!(parse(b"<13>hello", c).truncated);
    assert!(parse(b"garbage", c).truncated);
}

#[test]
fn every_prefix_of_valid_messages_is_handled() {
    let vectors: [&[u8]; 4] = [
        b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"][p@1 class=\"h\\\"i\"] \xEF\xBB\xBFmsg",
        b"<34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed",
        b"<13>2026-10-16T11:59:58.123+02:00 host app: x",
        b"<0>1 2003-08-24T05:14:15.000003-07:00 h a p m - x",
    ];
    for v in vectors {
        for end in 0..=v.len() {
            let m = parse(&v[..end], ctx());
            let _ = m.timestamp.to_string();
        }
    }
}
