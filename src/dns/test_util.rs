//! Builds DNS messages with hickory-proto, which serves as the oracle.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::svcb::{IpHint, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

pub fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

pub struct QuerySpec {
    pub id: u16,
    pub name: String,
    pub rtype: RecordType,
    pub recursion_desired: bool,
    pub checking_disabled: bool,
    pub edns: Option<(u16, bool)>,
}

impl QuerySpec {
    pub fn new(name: &str, rtype: RecordType) -> QuerySpec {
        QuerySpec {
            id: 0x1234,
            name: name.to_string(),
            rtype,
            recursion_desired: true,
            checking_disabled: false,
            edns: None,
        }
    }

    pub fn message(&self) -> Message {
        let mut message = Message::query();
        message.metadata.id = self.id;
        message.metadata.recursion_desired = self.recursion_desired;
        message.metadata.checking_disabled = self.checking_disabled;
        message.add_query(Query::query(name(&self.name), self.rtype));
        if let Some((udp_size, dnssec_ok)) = self.edns {
            let mut edns = Edns::new();
            edns.set_max_payload(udp_size);
            edns.set_dnssec_ok(dnssec_ok);
            message.set_edns(edns);
        }

        message
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.message().to_vec().unwrap()
    }
}

pub fn a(owner: &str, ttl: u32, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name(owner), ttl, RData::A(A(ip)))
}

pub fn aaaa(owner: &str, ttl: u32, ip: Ipv6Addr) -> Record {
    Record::from_rdata(name(owner), ttl, RData::AAAA(AAAA(ip)))
}

pub fn cname(owner: &str, ttl: u32, target: &str) -> Record {
    Record::from_rdata(name(owner), ttl, RData::CNAME(CNAME(name(target))))
}

pub fn soa(owner: &str, ttl: u32, minimum: u32) -> Record {
    let soa = SOA::new(
        name("ns.example.com."),
        name("hostmaster.example.com."),
        1,
        3600,
        600,
        86400,
        minimum,
    );

    Record::from_rdata(name(owner), ttl, RData::SOA(soa))
}

pub fn https(owner: &str, ttl: u32, v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> Record {
    let mut params = Vec::new();
    if !v4.is_empty() {
        let hints = IpHint(v4.iter().map(|ip| A(*ip)).collect());
        params.push((SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(hints)));
    }

    if !v6.is_empty() {
        let hints = IpHint(v6.iter().map(|ip| AAAA(*ip)).collect());
        params.push((SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(hints)));
    }

    let svcb = SVCB::new(1, Name::root(), params);

    Record::from_rdata(name(owner), ttl, RData::HTTPS(HTTPS(svcb)))
}

#[derive(Default)]
pub struct ResponseSpec {
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub rcode: u8,
    pub edns: Option<u16>,
}

impl ResponseSpec {
    pub fn bytes(&self, query: &QuerySpec) -> Vec<u8> {
        let mut message = Message::new(query.id, MessageType::Response, OpCode::Query);
        message.metadata.recursion_desired = query.recursion_desired;
        message.metadata.recursion_available = true;
        message.metadata.response_code = ResponseCode::from(0, self.rcode);
        message.add_query(Query::query(name(&query.name), query.rtype));
        message.add_answers(self.answers.clone());
        message.add_authorities(self.authorities.clone());
        message.add_additionals(self.additionals.clone());
        if let Some(udp_size) = self.edns {
            let mut edns = Edns::new();
            edns.set_max_payload(udp_size);
            message.set_edns(edns);
        }

        message.to_vec().unwrap()
    }
}

pub fn parse(bytes: &[u8]) -> Message {
    Message::from_vec(bytes).unwrap()
}

/// A TXT record whose rdata is about `size` bytes.
pub fn txt(owner: &str, ttl: u32, size: usize) -> Record {
    let strings: Vec<String> = (0..size / 256).map(|_| "x".repeat(255)).collect();

    Record::from_rdata(name(owner), ttl, RData::TXT(TXT::new(strings)))
}

/// Offsets inside `response_with_opt_before_other_additionals`.
pub const OPT_BEFORE_ADDITIONALS_OPT_START: usize = 49;
pub const OPT_BEFORE_ADDITIONALS_FIRST_START: usize = 60;

/// A reply to `www.example.com A` written by hand because hickory always
/// puts the OPT record last: one A answer, then the additional section
/// `OPT, ns.example.com A, ns.example.com AAAA, ns.example.com CNAME
/// alt.ns.example.com`. The last two records point back at the first one
/// (owner name, CNAME target), so moving anything before them breaks their
/// compression pointers.
pub fn response_with_opt_before_other_additionals() -> Vec<u8> {
    let mut bytes = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 4];
    bytes.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
    bytes.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
    assert_eq!(bytes.len(), OPT_BEFORE_ADDITIONALS_OPT_START);

    bytes.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    assert_eq!(bytes.len(), OPT_BEFORE_ADDITIONALS_FIRST_START);

    bytes.extend_from_slice(&[2, b'n', b's', 0xC0, 16, 0, 1, 0, 1, 0, 0, 2, 88, 0, 4]);
    bytes.extend_from_slice(&[192, 0, 2, 53]);
    bytes.extend_from_slice(&[0xC0, 60, 0, 28, 0, 1, 0, 0, 3, 132, 0, 16]);
    bytes.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
    ]);
    bytes.extend_from_slice(&[0xC0, 60, 0, 5, 0, 1, 0, 0, 3, 132, 0, 6]);
    bytes.extend_from_slice(&[3, b'a', b'l', b't', 0xC0, 60]);

    bytes
}
