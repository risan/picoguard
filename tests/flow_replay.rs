//! The full-flow golden replies: picoguard answers every query of `flow.case` from the same
//! scripted upstream AdGuard Home v0.107.79 was given, and the reply must equal the one the
//! real binary gave (rcode, flags, records and TTLs; not the ID, not the OPT record).

mod common;

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use common::harness::{self, Running, name, reply_to};
use common::{fixtures_dir, load_flow_case, read_text};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::svcb::{IpHint, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, TXT};
use hickory_proto::rr::{RData, Record, RecordType};
use picoguard::filter::engine::{CompiledList, Engine};
use picoguard::filter::parse::ListFormat;

struct Scripted {
    rcode: ResponseCode,
    records: Vec<Record>,
}

fn parse_record(line: &str) -> Record {
    let mut fields = line.splitn(5, ' ');
    let owner = fields.next().unwrap();
    let ttl: u32 = fields.next().unwrap().parse().unwrap();
    assert_eq!(fields.next(), Some("IN"), "{line}");
    let rtype = fields.next().unwrap();
    let rdata = fields.next().unwrap_or_default();

    let data = match rtype {
        "A" => RData::A(A(rdata.parse::<Ipv4Addr>().unwrap())),
        "AAAA" => RData::AAAA(AAAA(rdata.parse::<Ipv6Addr>().unwrap())),
        "CNAME" => RData::CNAME(CNAME(name(rdata))),
        "TXT" => RData::TXT(TXT::new(vec![rdata.trim_matches('"').to_string()])),
        "HTTPS" => RData::HTTPS(HTTPS(parse_https(rdata))),
        other => panic!("unsupported script type {other}"),
    };

    Record::from_rdata(name(owner), ttl, data)
}

/// `1 . [ipv4hint=a,b] [ipv6hint=c,d]`
fn parse_https(rdata: &str) -> SVCB {
    let mut fields = rdata.split_whitespace();
    let priority: u16 = fields.next().unwrap().parse().unwrap();
    let target = name(fields.next().unwrap());
    let mut params = Vec::new();
    for field in fields {
        let (key, value) = field.split_once('=').unwrap();
        match key {
            "ipv4hint" => {
                let hints = value.split(',').map(|ip| A(ip.parse().unwrap())).collect();
                params.push((
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(hints)),
                ));
            }
            "ipv6hint" => {
                let hints = value
                    .split(',')
                    .map(|ip| AAAA(ip.parse().unwrap()))
                    .collect();
                params.push((
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(hints)),
                ));
            }
            other => panic!("unsupported HTTPS parameter {other}"),
        }
    }

    SVCB::new(priority, target, params)
}

/// The `[upstream]` section: `(lowercase name, type)` to the scripted answer.
fn parse_script(text: &str) -> HashMap<(String, RecordType), Scripted> {
    let mut script = HashMap::new();
    let mut current: Option<(String, RecordType)> = None;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Some(question) = line.strip_prefix("Q ") {
            let (owner, rtype) = question.split_once(' ').unwrap();
            let key = (
                format!("{}.", owner.to_ascii_lowercase()),
                rtype.parse().unwrap(),
            );
            script.insert(
                key.clone(),
                Scripted {
                    rcode: ResponseCode::NoError,
                    records: Vec::new(),
                },
            );
            current = Some(key);
        } else if let Some(rcode) = line.strip_prefix("RCODE ") {
            assert_eq!(rcode, "NXDOMAIN");
            script.get_mut(current.as_ref().unwrap()).unwrap().rcode = ResponseCode::NXDomain;
        } else {
            script
                .get_mut(current.as_ref().unwrap())
                .unwrap()
                .records
                .push(parse_record(line));
        }
    }

    script
}

fn compile(text: &str) -> Arc<CompiledList> {
    Arc::new(CompiledList::from_text(ListFormat::Adblock, text).0)
}

// ---- Formatting a reply like tools/agh-flow ----

fn rcode_text(rcode: ResponseCode) -> &'static str {
    match u16::from(rcode) {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        other => panic!("rcode {other}"),
    }
}

fn flags_text(message: &Message) -> String {
    let metadata = &message.metadata;
    let mut text = String::new();
    for (name, set) in [
        ("qr", true),
        ("aa", metadata.authoritative),
        ("tc", metadata.truncation),
        ("rd", metadata.recursion_desired),
        ("ra", metadata.recursion_available),
        ("ad", metadata.authentic_data),
        ("cd", metadata.checking_disabled),
    ] {
        if set {
            text.push(' ');
            text.push_str(name);
        }
    }

    text
}

fn rdata_text(data: &RData) -> String {
    match data {
        RData::A(address) => address.0.to_string(),
        RData::AAAA(address) => address.0.to_string(),
        RData::CNAME(target) => target.0.to_string(),
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|part| format!("\"{}\"", String::from_utf8_lossy(part)))
            .collect::<Vec<_>>()
            .join(" "),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
        ),
        RData::HTTPS(https) => {
            let mut text = format!("{} {}", https.svc_priority, https.target_name);
            for (key, value) in &https.svc_params {
                let hints = match value {
                    SvcParamValue::Ipv4Hint(hints) => {
                        hints.0.iter().map(|ip| ip.0.to_string()).collect()
                    }
                    SvcParamValue::Ipv6Hint(hints) => {
                        hints.0.iter().map(|ip| ip.0.to_string()).collect()
                    }
                    other => panic!("unsupported parameter {other:?}"),
                };
                let hints: Vec<String> = hints;
                text.push_str(&format!(" {key}=\"{}\"", hints.join(",")));
            }

            text
        }
        other => panic!("unsupported record data {other:?}"),
    }
}

fn record_text(section: &str, record: &Record) -> String {
    format!(
        "{section} {} {} {} {}",
        record.name,
        record.ttl,
        record.record_type(),
        rdata_text(&record.data)
    )
}

fn reply_text(query: &str, message: &Message) -> String {
    let mut lines = vec![
        format!("Q {query}"),
        format!(
            "rcode {} flags{}",
            rcode_text(message.metadata.response_code),
            flags_text(message)
        ),
    ];
    for (section, records) in [
        ("an", &message.answers),
        ("ns", &message.authorities),
        ("ar", &message.additionals),
    ] {
        lines.extend(records.iter().map(|record| record_text(section, record)));
    }

    lines.join("\n")
}

#[tokio::test]
async fn picoguard_replies_like_adguard_home_to_every_flow_query() {
    let case = load_flow_case();
    let script = Arc::new(parse_script(&case.upstream));
    let upstream = harness::fake_upstream({
        let script = Arc::clone(&script);

        move |query| {
            let question = &query.queries[0];
            let key = (
                question.name().to_ascii().to_ascii_lowercase(),
                question.query_type(),
            );
            let scripted = script
                .get(&key)
                .unwrap_or_else(|| panic!("unscripted upstream question {key:?}"));
            let mut reply = reply_to(query, scripted.records.clone());
            reply.metadata.response_code = scripted.rcode;

            vec![(std::time::Duration::ZERO, reply)]
        }
    })
    .await;

    let mut main = Vec::new();
    if !case.user.is_empty() {
        main.push(compile(&case.user));
    }

    main.extend(case.main.iter().map(|text| compile(text)));
    let allow = case.allow.iter().map(|text| compile(text)).collect();
    let server: Running = harness::start(
        &harness::config_for(&upstream),
        Arc::new(Engine::new(main, allow)),
    )
    .await;

    let expected = read_text(&fixtures_dir().join("golden/flow/flow.expected"))
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let expected: HashMap<&str, &str> = expected
        .split("\n\n")
        .filter_map(|block| {
            let block = block.trim_end();
            let first = block.lines().next()?.strip_prefix("Q ")?;

            Some((first, block))
        })
        .collect();

    let mut matched = 0;
    let mut mismatches = Vec::new();
    for query in &case.queries {
        let text = format!("{} {}", query.input, query.check_type);
        let reply = harness::ask(&server, &query.input, query.check_type.parse().unwrap()).await;
        let actual = reply_text(&text, &reply);
        let golden = expected[text.as_str()];
        if actual == golden {
            matched += 1;
        } else {
            mismatches.push(format!("--- expected\n{golden}\n--- picoguard\n{actual}"));
        }
    }

    println!("flow: {matched} of {} replies match", case.queries.len());
    assert!(
        mismatches.is_empty(),
        "{} differ\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert_eq!(matched, 60);
}
