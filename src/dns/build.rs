use std::net::IpAddr;

use super::wire::{
    CLASS_IN, HEADER_LEN, Header, MAX_MESSAGE_LEN, MAX_NAME_LEN, Query, flags, rcode, remove_opt,
    rtype,
};

const CLASSIC_UDP_LIMIT: u16 = 512;
const OPT_RECORD_LEN: usize = 11;
/// Owner (1 byte), type and class (4): the TTL field starts here, and its
/// first byte is the extended RCODE.
const OPT_EXTENDED_RCODE_AT: usize = 5;
const EDNS_DO: u32 = 0x8000;
const NAME_POINTER_TO_QUESTION: [u8; 2] = [0xC0, HEADER_LEN as u8];

const ANSWER_COUNT: usize = 6;
const AUTHORITY_COUNT: usize = 8;
const ADDITIONAL_COUNT: usize = 10;

// The SOA values AdGuard Home puts in blocked NODATA replies.
const SOA_MNAME: &[&[u8]] = &[b"fake-for-negative-caching", b"adguard", b"com"];
const SOA_RNAME_LABEL: &[u8] = b"hostmaster";
const SOA_SERIAL: u32 = 100_500;
const SOA_REFRESH: u32 = 1800;
const SOA_RETRY: u32 = 900;
const SOA_EXPIRE: u32 = 604_800;
const SOA_MINIMUM: u32 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp,
}

/// How cached TTLs reach a client: clamped to the configured range, then aged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlRule {
    pub min: u32,
    pub max: u32,
    pub age: u32,
}

impl TtlRule {
    pub fn apply(&self, ttl: u32) -> u32 {
        ttl.clamp(self.min, self.max).saturating_sub(self.age)
    }
}

/// An upstream reply as the cache keeps it. `bytes` starts with a header and
/// exactly the client's question, and `ttl_offsets` and `opt_start` were taken
/// from a successful `ResponseInfo::parse` of `bytes`.
#[derive(Debug, Clone, Copy)]
pub struct ReplyParts<'a> {
    pub bytes: &'a [u8],
    pub ttl_offsets: &'a [u16],
    pub opt_start: Option<u16>,
}

/// Writes the reply to one client query.
pub struct Reply<'q, 'a> {
    query: &'q Query<'a>,
    udp_size: u16,
    protocol: Protocol,
}

impl<'q, 'a> Reply<'q, 'a> {
    /// `udp_size` is the EDNS payload size picoguard announces.
    pub fn new(query: &'q Query<'a>, udp_size: u16, protocol: Protocol) -> Reply<'q, 'a> {
        Reply {
            query,
            udp_size,
            protocol,
        }
    }

    /// An empty reply with only the question and the given rcode.
    pub fn error(&self, rcode: u8, out: &mut Vec<u8>) {
        self.begin(rcode, out);
        self.end(out, 0);
    }

    /// AdGuard "default" blocking: A is 0.0.0.0, AAAA is ::, HTTPS is empty,
    /// every other type is NODATA with a SOA.
    pub fn blocked(&self, ttl: u32, out: &mut Vec<u8>) {
        self.begin(rcode::NOERROR, out);

        match self.query.question.qtype {
            rtype::A => {
                self.push_answer(rtype::A, ttl, &[0; 4], out);
            }

            rtype::AAAA => {
                self.push_answer(rtype::AAAA, ttl, &[0; 16], out);
            }

            rtype::HTTPS => {}

            _ => {
                self.push_soa(ttl, out);
            }
        }

        self.end(out, 0);
    }

    /// Answers an A or AAAA question with the addresses of that family.
    pub fn addresses(&self, addresses: &[IpAddr], ttl: u32, out: &mut Vec<u8>) {
        self.begin(rcode::NOERROR, out);

        for address in addresses {
            match (self.query.question.qtype, address) {
                (rtype::A, IpAddr::V4(address)) => {
                    self.push_answer(rtype::A, ttl, &address.octets(), out);
                }

                (rtype::AAAA, IpAddr::V6(address)) => {
                    self.push_answer(rtype::AAAA, ttl, &address.octets(), out);
                }

                _ => {}
            }
        }

        self.end(out, 0);
    }

    /// Rebuilds a stored upstream reply for this client: its ID, RD and CD, our
    /// RA, its question letter case, aged TTLs and our OPT record.
    pub fn from_upstream(&self, parts: ReplyParts<'_>, ttl_rule: TtlRule, out: &mut Vec<u8>) {
        let question_end = HEADER_LEN + self.query.question_bytes().len();
        if parts.bytes.len() < question_end {
            self.error(rcode::SERVFAIL, out);

            return;
        }

        // The upper 8 bits of the RCODE live in the OPT record's TTL field. Only
        // a client that sent an OPT can be given them.
        let extended_rcode = parts
            .opt_start
            .and_then(|start| parts.bytes.get(usize::from(start) + OPT_EXTENDED_RCODE_AT))
            .copied()
            .unwrap_or(0);
        if extended_rcode != 0 && self.query.edns.is_none() {
            self.error(rcode::SERVFAIL, out);

            return;
        }

        out.clear();
        out.extend_from_slice(parts.bytes);
        out[HEADER_LEN..question_end].copy_from_slice(self.query.question_bytes());
        out[0..2].copy_from_slice(&self.query.id().to_be_bytes());
        out[2..4].copy_from_slice(&self.upstream_flags(parts.bytes).to_be_bytes());

        for &offset in parts.ttl_offsets {
            let offset = usize::from(offset);
            if let Some(field) = out.get_mut(offset..offset + 4) {
                let ttl = u32::from_be_bytes([field[0], field[1], field[2], field[3]]);
                field.copy_from_slice(&ttl_rule.apply(ttl).to_be_bytes());
            }
        }

        if let Some(opt_start) = parts.opt_start
            && remove_opt(out, usize::from(opt_start)).is_err()
        {
            self.error(rcode::SERVFAIL, out);

            return;
        }

        self.end(out, extended_rcode);

        // Our OPT record can be larger than the one it replaces.
        if out.len() > MAX_MESSAGE_LEN {
            self.error(rcode::SERVFAIL, out);
        }
    }

    fn upstream_flags(&self, upstream: &[u8]) -> u16 {
        let upstream_flags = u16::from_be_bytes([upstream[2], upstream[3]]);
        let kept = upstream_flags & (flags::AA | flags::TC | flags::RCODE_MASK);
        let authenticated = if self.query.dnssec_ok() {
            upstream_flags & flags::AD
        } else {
            0
        };

        self.client_flags() | kept | authenticated
    }

    fn client_flags(&self) -> u16 {
        let mut reply_flags = flags::QR | flags::RA;
        if self.query.header.recursion_desired() {
            reply_flags |= flags::RD;
        }

        if self.query.header.checking_disabled() {
            reply_flags |= flags::CD;
        }

        reply_flags
    }

    fn begin(&self, rcode: u8, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(&self.query.id().to_be_bytes());
        out.extend_from_slice(&(self.client_flags() | u16::from(rcode)).to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(self.query.question_bytes());
    }

    fn push_answer(&self, rtype: u16, ttl: u32, rdata: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&NAME_POINTER_TO_QUESTION);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        add_to_count(out, ANSWER_COUNT);
    }

    fn push_soa(&self, ttl: u32, out: &mut Vec<u8>) {
        let mut rdata = Vec::with_capacity(96);
        for label in SOA_MNAME {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label);
        }

        rdata.push(0);

        rdata.push(SOA_RNAME_LABEL.len() as u8);
        rdata.extend_from_slice(SOA_RNAME_LABEL);
        // The pointer expands to the label followed by the question name, which
        // is too long for a name when the question name is nearly at the limit.
        let question_name_len = self.query.question.name.as_wire().len();
        let mailbox_fits = SOA_RNAME_LABEL.len() + 1 + question_name_len <= MAX_NAME_LEN;
        if self.query.question.name.is_root() || !mailbox_fits {
            rdata.push(0);
        } else {
            rdata.extend_from_slice(&NAME_POINTER_TO_QUESTION);
        }

        for field in [SOA_SERIAL, SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_MINIMUM] {
            rdata.extend_from_slice(&field.to_be_bytes());
        }

        out.extend_from_slice(&NAME_POINTER_TO_QUESTION);
        out.extend_from_slice(&rtype::SOA.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
        add_to_count(out, AUTHORITY_COUNT);
    }

    /// Truncates for UDP when needed, then appends our OPT record if the client
    /// sent one, carrying `extended_rcode`. TCP replies are never truncated.
    fn end(&self, out: &mut Vec<u8>, extended_rcode: u8) {
        let opt_len = if self.query.edns.is_some() {
            OPT_RECORD_LEN
        } else {
            0
        };

        if self.protocol == Protocol::Udp && out.len() + opt_len > self.udp_limit() {
            out.truncate(HEADER_LEN + self.query.question_bytes().len());
            out[ANSWER_COUNT..HEADER_LEN].fill(0);
            let truncated_flags = u16::from_be_bytes([out[2], out[3]]) | flags::TC;
            out[2..4].copy_from_slice(&truncated_flags.to_be_bytes());
        }

        if self.query.edns.is_some() {
            push_opt_record(out, self.udp_size, self.query.dnssec_ok(), extended_rcode);
            add_to_count(out, ADDITIONAL_COUNT);
        }
    }

    fn udp_limit(&self) -> usize {
        let advertised = self
            .query
            .edns
            .map_or(CLASSIC_UDP_LIMIT, |edns| edns.udp_size);

        usize::from(advertised.max(CLASSIC_UDP_LIMIT))
    }
}

fn add_to_count(message: &mut [u8], at: usize) {
    let count = u16::from_be_bytes([message[at], message[at + 1]]) + 1;
    message[at..at + 2].copy_from_slice(&count.to_be_bytes());
}

/// Reply to a packet whose question could not be read: header only.
pub fn header_only(request: &Header, rcode: u8, out: &mut Vec<u8>) {
    let mut reply_flags = flags::QR | flags::RA | (request.flags & flags::OPCODE_MASK);
    if request.recursion_desired() {
        reply_flags |= flags::RD;
    }

    out.clear();
    out.extend_from_slice(&request.id.to_be_bytes());
    out.extend_from_slice(&(reply_flags | u16::from(rcode)).to_be_bytes());
    out.extend_from_slice(&[0; 8]);
}

/// What the pipeline keeps of a client query while it waits for the upstream:
/// the ID, flags, the question as sent, and an OPT record with the client's
/// size and DO bit. A padded 64 KiB query shrinks to a few dozen bytes.
pub fn compact_query(query: &Query<'_>) -> Vec<u8> {
    let question = query.question_bytes();
    let opt_len = if query.edns.is_some() {
        OPT_RECORD_LEN
    } else {
        0
    };
    let mut out = Vec::with_capacity(HEADER_LEN + question.len() + opt_len);

    out.extend_from_slice(&query.id().to_be_bytes());
    out.extend_from_slice(&query.header.flags.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    out.extend_from_slice(&u16::from(query.edns.is_some()).to_be_bytes());
    out.extend_from_slice(question);

    if let Some(edns) = query.edns {
        push_opt_record(&mut out, edns.udp_size, query.dnssec_ok(), 0);
    }

    out
}

/// The query picoguard sends upstream: ID 0 (the transport sets it), RD and CD
/// from the client, a lowercase question, and an OPT record with our size and
/// the client's DO bit but none of its options.
pub fn upstream_query(query: &Query<'_>, udp_size: u16) -> Vec<u8> {
    let mut query_flags = 0;
    if query.header.recursion_desired() {
        query_flags |= flags::RD;
    }

    if query.header.checking_disabled() {
        query_flags |= flags::CD;
    }

    let name = query.question.name.as_wire();
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 4 + OPT_RECORD_LEN);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&query_flags.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]);
    out.extend_from_slice(name);
    out.extend_from_slice(&query.question.qtype.to_be_bytes());
    out.extend_from_slice(&query.question.qclass.to_be_bytes());
    push_opt_record(&mut out, udp_size, query.dnssec_ok(), 0);

    out
}

fn push_opt_record(out: &mut Vec<u8>, udp_size: u16, dnssec_ok: bool, extended_rcode: u8) {
    let ttl_field = (u32::from(extended_rcode) << 24) | if dnssec_ok { EDNS_DO } else { 0 };

    out.push(0);
    out.extend_from_slice(&rtype::OPT.to_be_bytes());
    out.extend_from_slice(&udp_size.to_be_bytes());
    out.extend_from_slice(&ttl_field.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::{RData, RecordType};

    use super::*;
    use crate::dns::test_util::{
        QuerySpec, ResponseSpec, a, cname, parse, response_with_opt_before_other_additionals, soa,
        txt,
    };
    use crate::dns::wire::ResponseInfo;

    const SERVER_UDP_SIZE: u16 = 1232;

    fn built(
        spec: &QuerySpec,
        protocol: Protocol,
        write: impl FnOnce(&Reply, &mut Vec<u8>),
    ) -> Message {
        let bytes = spec.bytes();
        let query = Query::parse(&bytes).unwrap();
        let mut out = Vec::new();

        write(&Reply::new(&query, SERVER_UDP_SIZE, protocol), &mut out);

        parse(&out)
    }

    fn blocked(name: &str, rtype: RecordType) -> Message {
        built(&QuerySpec::new(name, rtype), Protocol::Udp, |reply, out| {
            reply.blocked(10, out);
        })
    }

    fn parts_of(bytes: &[u8]) -> (Vec<u16>, Option<u16>) {
        let info = ResponseInfo::parse(bytes).unwrap();

        (info.ttl_offsets, info.opt_start)
    }

    fn from_upstream(
        spec: &QuerySpec,
        upstream: &[u8],
        protocol: Protocol,
        ttl_rule: TtlRule,
    ) -> Vec<u8> {
        let bytes = spec.bytes();
        let query = Query::parse(&bytes).unwrap();
        let (ttl_offsets, opt_start) = parts_of(upstream);
        let parts = ReplyParts {
            bytes: upstream,
            ttl_offsets: &ttl_offsets,
            opt_start,
        };
        let mut out = Vec::new();

        Reply::new(&query, SERVER_UDP_SIZE, protocol).from_upstream(parts, ttl_rule, &mut out);

        out
    }

    fn no_aging() -> TtlRule {
        TtlRule {
            min: 0,
            max: u32::MAX,
            age: 0,
        }
    }

    #[test]
    fn blocked_a_is_the_null_address_with_the_blocked_ttl() {
        let message = blocked("Ads.Example.com.", RecordType::A);

        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].ttl, 10);
        assert_eq!(message.answers[0].name.to_ascii(), "Ads.Example.com.");
        let RData::A(address) = &message.answers[0].data else {
            panic!("expected an A record");
        };

        assert_eq!(address.0, std::net::Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn blocked_aaaa_is_the_unspecified_address() {
        let message = blocked("ads.example.com.", RecordType::AAAA);

        let RData::AAAA(address) = &message.answers[0].data else {
            panic!("expected an AAAA record");
        };

        assert_eq!(address.0, std::net::Ipv6Addr::UNSPECIFIED);
        assert_eq!(message.answers[0].ttl, 10);
    }

    #[test]
    fn blocked_https_is_empty_noerror() {
        let message = blocked("ads.example.com.", RecordType::HTTPS);

        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.is_empty());
        assert!(message.authorities.is_empty());
    }

    #[test]
    fn other_blocked_types_get_nodata_with_adguards_soa() {
        for rtype in [RecordType::MX, RecordType::TXT, RecordType::NS] {
            let message = blocked("ads.example.com.", rtype);

            assert_eq!(message.metadata.response_code, ResponseCode::NoError);
            assert!(message.answers.is_empty());
            assert_eq!(message.authorities.len(), 1);
            let soa = &message.authorities[0];
            assert_eq!(soa.ttl, 10);
            assert_eq!(soa.name.to_ascii(), "ads.example.com.");
            let RData::SOA(data) = &soa.data else {
                panic!("expected a SOA record");
            };

            assert_eq!(
                data.mname.to_ascii(),
                "fake-for-negative-caching.adguard.com."
            );
            assert_eq!(data.rname.to_ascii(), "hostmaster.ads.example.com.");
            assert_eq!(data.serial, 100_500);
            assert_eq!(data.refresh, 1800);
            assert_eq!(data.retry, 900);
            assert_eq!(data.expire, 604_800);
            assert_eq!(data.minimum, 86_400);
        }
    }

    #[test]
    fn nodata_soa_for_the_root_name_has_a_bare_mailbox() {
        let message = blocked(".", RecordType::TXT);

        let RData::SOA(data) = &message.authorities[0].data else {
            panic!("expected a SOA record");
        };

        assert_eq!(data.rname.to_ascii(), "hostmaster.");
    }

    /// A name of three 63-byte labels and a last one of `last_label` bytes,
    /// which is `194 + last_label` bytes on the wire.
    fn long_name(last_label: usize) -> String {
        let long = "a".repeat(63);

        format!("{long}.{long}.{long}.{}.", "b".repeat(last_label))
    }

    fn mailbox_of_nodata_soa(name: &str) -> String {
        let message = blocked(name, RecordType::TXT);
        assert_eq!(message.authorities[0].name.to_ascii(), name);
        let RData::SOA(data) = &message.authorities[0].data else {
            panic!("expected a SOA record");
        };

        data.rname.to_ascii()
    }

    #[test]
    fn the_nodata_mailbox_falls_back_when_hostmaster_plus_the_name_would_pass_255_bytes() {
        // "hostmaster." adds 11 bytes: a 244-byte name still fits, 245 does not.
        let fits = long_name(50);
        let one_too_long = long_name(51);
        let longest = long_name(61);

        assert_eq!(mailbox_of_nodata_soa(&fits), format!("hostmaster.{fits}"));
        assert_eq!(mailbox_of_nodata_soa(&one_too_long), "hostmaster.");
        assert_eq!(mailbox_of_nodata_soa(&longest), "hostmaster.");
    }

    #[test]
    fn replies_echo_id_question_case_rd_and_cd_and_set_ra() {
        let mut spec = QuerySpec::new("MiXed.Example.com.", RecordType::A);
        spec.id = 0xABCD;
        spec.checking_disabled = true;

        let message = built(&spec, Protocol::Udp, |reply, out| reply.blocked(10, out));

        assert_eq!(message.metadata.id, 0xABCD);
        assert!(message.metadata.recursion_desired);
        assert!(message.metadata.recursion_available);
        assert!(message.metadata.checking_disabled);
        assert_eq!(message.queries[0].name().to_ascii(), "MiXed.Example.com.");

        spec.recursion_desired = false;
        let message = built(&spec, Protocol::Udp, |reply, out| reply.blocked(10, out));
        assert!(!message.metadata.recursion_desired);
    }

    #[test]
    fn opt_is_added_only_when_the_client_sent_one_and_echoes_do() {
        let mut spec = QuerySpec::new("example.com.", RecordType::A);

        let without = built(&spec, Protocol::Udp, |reply, out| reply.blocked(10, out));
        spec.edns = Some((4096, true));
        let with = built(&spec, Protocol::Udp, |reply, out| reply.blocked(10, out));
        spec.edns = Some((4096, false));
        let without_do = built(&spec, Protocol::Udp, |reply, out| reply.blocked(10, out));

        assert!(without.edns.is_none());
        let edns = with.edns.unwrap();
        assert_eq!(edns.max_payload(), SERVER_UDP_SIZE);
        assert!(edns.flags().dnssec_ok);
        assert!(!without_do.edns.unwrap().flags().dnssec_ok);
    }

    #[test]
    fn error_replies_carry_the_question_and_the_rcode() {
        let spec = QuerySpec::new("example.com.", RecordType::A);
        let cases = [
            (rcode::SERVFAIL, ResponseCode::ServFail),
            (rcode::REFUSED, ResponseCode::Refused),
            (rcode::NOTIMP, ResponseCode::NotImp),
            (rcode::NXDOMAIN, ResponseCode::NXDomain),
            (rcode::FORMERR, ResponseCode::FormErr),
        ];

        for (code, expected) in cases {
            let message = built(&spec, Protocol::Tcp, |reply, out| reply.error(code, out));

            assert_eq!(message.metadata.response_code, expected);
            assert_eq!(message.queries.len(), 1);
            assert!(message.answers.is_empty());
        }
    }

    #[test]
    fn header_only_reply_has_the_id_and_no_sections() {
        let mut bytes = QuerySpec::new("example.com.", RecordType::A).bytes();
        bytes[2] |= 4 << 3;
        let header = Header::parse(&bytes).unwrap();
        let mut out = Vec::new();

        header_only(&header, rcode::NOTIMP, &mut out);

        let message = parse(&out);
        assert_eq!(message.metadata.id, 0x1234);
        assert_eq!(message.metadata.response_code, ResponseCode::NotImp);
        assert!(message.queries.is_empty());
        assert_eq!(out.len(), HEADER_LEN);
        assert_eq!(Header::parse(&out).unwrap().opcode(), 4);
    }

    #[test]
    fn address_replies_keep_only_the_queried_family() {
        let addresses: Vec<IpAddr> = vec![
            "10.0.0.1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        ];

        let v4 = built(
            &QuerySpec::new("host.example.", RecordType::A),
            Protocol::Udp,
            |reply, out| reply.addresses(&addresses, 10, out),
        );
        let v6 = built(
            &QuerySpec::new("host.example.", RecordType::AAAA),
            Protocol::Udp,
            |reply, out| reply.addresses(&addresses, 10, out),
        );

        assert_eq!(v4.answers.len(), 2);
        assert_eq!(v6.answers.len(), 1);
        assert_eq!(v4.answers[0].ttl, 10);
    }

    #[test]
    fn upstream_reply_is_rebuilt_for_the_client() {
        let upstream_query = QuerySpec::new("example.com.", RecordType::A);
        let upstream = ResponseSpec {
            answers: vec![
                cname("example.com.", 300, "edge.example.net."),
                a("edge.example.net.", 120, [192, 0, 2, 1].into()),
            ],
            authorities: vec![soa("example.net.", 600, 60)],
            edns: Some(4096),
            ..ResponseSpec::default()
        }
        .bytes(&upstream_query);
        let mut client = QuerySpec::new("EXAMPLE.com.", RecordType::A);
        client.id = 0x7777;
        client.recursion_desired = false;

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        let message = parse(&out);
        assert_eq!(message.metadata.id, 0x7777);
        assert!(!message.metadata.recursion_desired);
        assert!(message.metadata.recursion_available);
        assert_eq!(message.queries[0].name().to_ascii(), "EXAMPLE.com.");
        assert_eq!(message.answers.len(), 2);
        assert_eq!(message.authorities.len(), 1);
        assert!(message.edns.is_none(), "client sent no OPT");
        assert!(message.additionals.is_empty());
    }

    #[test]
    fn upstream_opt_is_replaced_by_ours_when_the_client_sent_one() {
        let upstream_query = QuerySpec::new("example.com.", RecordType::A);
        let upstream = ResponseSpec {
            answers: vec![a("example.com.", 120, [192, 0, 2, 1].into())],
            edns: Some(4096),
            ..ResponseSpec::default()
        }
        .bytes(&upstream_query);
        let mut client = QuerySpec::new("example.com.", RecordType::A);
        client.edns = Some((1400, true));

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        let message = parse(&out);
        let edns = message.edns.unwrap();
        assert_eq!(edns.max_payload(), SERVER_UDP_SIZE);
        assert!(edns.flags().dnssec_ok);
        assert_eq!(message.answers.len(), 1);
    }

    #[test]
    fn client_opt_is_added_when_the_upstream_reply_has_none() {
        let upstream_query = QuerySpec::new("example.com.", RecordType::A);
        let upstream = ResponseSpec {
            answers: vec![a("example.com.", 120, [192, 0, 2, 1].into())],
            ..ResponseSpec::default()
        }
        .bytes(&upstream_query);
        let mut client = QuerySpec::new("example.com.", RecordType::A);
        client.edns = Some((1400, false));

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        assert_eq!(parse(&out).edns.unwrap().max_payload(), SERVER_UDP_SIZE);
    }

    #[test]
    fn ttls_are_clamped_then_aged() {
        let upstream_query = QuerySpec::new("example.com.", RecordType::A);
        let upstream = ResponseSpec {
            answers: vec![
                a("example.com.", 5, [192, 0, 2, 1].into()),
                a("example.com.", 100, [192, 0, 2, 2].into()),
                a("example.com.", 90_000, [192, 0, 2, 3].into()),
            ],
            ..ResponseSpec::default()
        }
        .bytes(&upstream_query);
        let client = QuerySpec::new("example.com.", RecordType::A);
        let rule = TtlRule {
            min: 30,
            max: 3600,
            age: 10,
        };

        let out = from_upstream(&client, &upstream, Protocol::Tcp, rule);

        let ttls: Vec<u32> = parse(&out)
            .answers
            .iter()
            .map(|record| record.ttl)
            .collect();
        assert_eq!(ttls, [20, 90, 3590]);
    }

    #[test]
    fn dnssec_flag_ad_is_kept_only_for_dnssec_clients() {
        let upstream_query = QuerySpec::new("example.com.", RecordType::A);
        let mut upstream = ResponseSpec {
            answers: vec![a("example.com.", 120, [192, 0, 2, 1].into())],
            ..ResponseSpec::default()
        }
        .bytes(&upstream_query);
        upstream[3] |= 0x20;
        let plain = QuerySpec::new("example.com.", RecordType::A);
        let mut dnssec = QuerySpec::new("example.com.", RecordType::A);
        dnssec.edns = Some((1232, true));

        let for_plain = from_upstream(&plain, &upstream, Protocol::Udp, no_aging());
        let for_dnssec = from_upstream(&dnssec, &upstream, Protocol::Udp, no_aging());

        assert!(!parse(&for_plain).metadata.authentic_data);
        assert!(parse(&for_dnssec).metadata.authentic_data);
    }

    fn large_answer(client: &QuerySpec) -> Vec<u8> {
        let upstream_query = QuerySpec::new(&client.name, RecordType::TXT);

        ResponseSpec {
            answers: vec![txt(&client.name, 60, 1600)],
            edns: Some(4096),
            ..ResponseSpec::default()
        }
        .bytes(&upstream_query)
    }

    #[test]
    fn a_1500_byte_answer_is_truncated_over_udp_without_edns() {
        let client = QuerySpec::new("big.example.com.", RecordType::TXT);
        let upstream = large_answer(&client);
        assert!(upstream.len() > 1500);

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        let message = parse(&out);
        assert!(message.metadata.truncation);
        assert!(message.answers.is_empty());
        assert_eq!(message.queries.len(), 1);
        assert!(out.len() <= 512);
    }

    #[test]
    fn a_1500_byte_answer_is_truncated_over_udp_with_edns_1232() {
        let mut client = QuerySpec::new("big.example.com.", RecordType::TXT);
        client.edns = Some((1232, false));
        let upstream = large_answer(&client);

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        let message = parse(&out);
        assert!(message.metadata.truncation);
        assert!(message.answers.is_empty());
        assert!(message.edns.is_some(), "OPT survives truncation");
        assert!(out.len() <= 1232);
    }

    #[test]
    fn the_client_size_decides_when_it_is_larger_than_the_reply() {
        let mut client = QuerySpec::new("big.example.com.", RecordType::TXT);
        client.edns = Some((4096, false));
        let upstream = large_answer(&client);

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        let message = parse(&out);
        assert!(!message.metadata.truncation);
        assert_eq!(message.answers.len(), 1);
    }

    #[test]
    fn tcp_replies_are_complete_with_and_without_edns() {
        for edns in [None, Some((1232, false))] {
            let mut client = QuerySpec::new("big.example.com.", RecordType::TXT);
            client.edns = edns;
            let upstream = large_answer(&client);

            let out = from_upstream(&client, &upstream, Protocol::Tcp, no_aging());

            let message = parse(&out);
            assert!(!message.metadata.truncation);
            assert_eq!(message.answers.len(), 1);
            assert!(out.len() > 1500);
        }
    }

    #[test]
    fn a_client_size_below_512_is_treated_as_512() {
        let mut client = QuerySpec::new("example.com.", RecordType::A);
        client.edns = Some((100, false));
        let upstream = ResponseSpec {
            answers: vec![a("example.com.", 120, [192, 0, 2, 1].into())],
            ..ResponseSpec::default()
        }
        .bytes(&QuerySpec::new("example.com.", RecordType::A));

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        assert!(!parse(&out).metadata.truncation);
    }

    /// An upstream reply of exactly `total` bytes: one TXT answer, and the OPT
    /// record last when `with_opt`.
    fn reply_of_len(client: &QuerySpec, total: usize, with_opt: bool) -> Vec<u8> {
        let mut bytes = client.bytes();
        let question_end = if client.edns.is_some() {
            bytes.len() - OPT_RECORD_LEN
        } else {
            bytes.len()
        };
        bytes.truncate(question_end);
        bytes[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        bytes[ANSWER_COUNT..ANSWER_COUNT + 2].copy_from_slice(&1u16.to_be_bytes());
        bytes[ADDITIONAL_COUNT..HEADER_LEN].copy_from_slice(&u16::from(with_opt).to_be_bytes());
        let opt_len = if with_opt { OPT_RECORD_LEN } else { 0 };
        let rdata_len = total - question_end - 12 - opt_len;
        bytes.extend_from_slice(&NAME_POINTER_TO_QUESTION);
        bytes.extend_from_slice(&16u16.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.extend_from_slice(&60u32.to_be_bytes());
        bytes.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        let mut remaining = rdata_len;
        while remaining > 0 {
            let chunk = (remaining - 1).min(255);
            bytes.push(chunk as u8);
            bytes.resize(bytes.len() + chunk, b'x');
            remaining -= 1 + chunk;
        }

        if with_opt {
            push_opt_record(&mut bytes, 4096, false, 0);
        }

        assert_eq!(bytes.len(), total);

        bytes
    }

    #[test]
    fn adding_our_opt_never_pushes_a_reply_past_the_65535_byte_limit() {
        let mut client = QuerySpec::new("big.example.com.", RecordType::TXT);
        client.edns = Some((1232, false));
        let cases = [
            (65_523, false, ResponseCode::NoError),
            (65_524, false, ResponseCode::NoError),
            (65_525, false, ResponseCode::ServFail),
            (65_535, false, ResponseCode::ServFail),
            (65_535, true, ResponseCode::NoError),
        ];

        for (upstream_len, with_opt, expected) in cases {
            let upstream = reply_of_len(&client, upstream_len, with_opt);

            let out = from_upstream(&client, &upstream, Protocol::Tcp, no_aging());

            assert!(out.len() <= 65_535, "{upstream_len}: {} bytes", out.len());
            let message = parse(&out);
            assert_eq!(message.metadata.response_code, expected, "{upstream_len}");
            assert!(message.edns.is_some(), "{upstream_len}");
        }
    }

    #[test]
    fn a_client_without_edns_gets_the_largest_reply_unchanged() {
        let client = QuerySpec::new("big.example.com.", RecordType::TXT);
        let upstream = reply_of_len(&client, 65_535, false);

        let out = from_upstream(&client, &upstream, Protocol::Tcp, no_aging());

        assert_eq!(out.len(), 65_535);
        assert_eq!(parse(&out).answers.len(), 1);
    }

    #[test]
    fn an_opt_record_before_other_additional_records_is_replaced_and_the_rest_kept() {
        let upstream = response_with_opt_before_other_additionals();
        let plain = QuerySpec::new("www.example.com.", RecordType::A);
        let mut with_edns = QuerySpec::new("www.example.com.", RecordType::A);
        with_edns.edns = Some((1400, true));
        let rule = TtlRule {
            age: 10,
            ..no_aging()
        };

        for (client, expects_opt) in [(plain, false), (with_edns, true)] {
            let out = from_upstream(&client, &upstream, Protocol::Tcp, rule);

            let message = parse(&out);
            assert_eq!(message.edns.is_some(), expects_opt);
            if expects_opt {
                assert_eq!(message.edns.unwrap().max_payload(), SERVER_UDP_SIZE);
            }

            assert_eq!(message.answers[0].ttl, 290);
            let additionals: Vec<(String, u32)> = message
                .additionals
                .iter()
                .map(|record| (record.name.to_ascii(), record.ttl))
                .collect();
            assert_eq!(
                additionals,
                [
                    ("ns.example.com.".to_string(), 590),
                    ("ns.example.com.".to_string(), 890),
                    ("ns.example.com.".to_string(), 890),
                ]
            );
            let RData::CNAME(target) = &message.additionals[2].data else {
                panic!("expected a CNAME");
            };

            assert_eq!(target.0.to_ascii(), "alt.ns.example.com.");
        }
    }

    fn reply_with_extended_rcode(extended_rcode: u8) -> Vec<u8> {
        let client = QuerySpec::new("example.com.", RecordType::A);
        let mut upstream = ResponseSpec {
            edns: Some(4096),
            ..ResponseSpec::default()
        }
        .bytes(&client);
        let opt_start = upstream.len() - OPT_RECORD_LEN;
        upstream[opt_start + 5] = extended_rcode;

        upstream
    }

    #[test]
    fn the_extended_rcode_of_the_upstream_goes_into_our_opt() {
        let upstream = reply_with_extended_rcode(1);
        let mut client = QuerySpec::new("example.com.", RecordType::A);
        client.edns = Some((1232, true));

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        let message = parse(&out);
        assert_eq!(u16::from(message.metadata.response_code), 16, "BADVERS");
        let edns = message.edns.unwrap();
        assert_eq!(edns.max_payload(), SERVER_UDP_SIZE);
        assert!(edns.flags().dnssec_ok);
    }

    #[test]
    fn a_client_without_edns_cannot_get_an_extended_rcode_and_gets_servfail() {
        let upstream = reply_with_extended_rcode(1);
        let client = QuerySpec::new("example.com.", RecordType::A);

        let out = from_upstream(&client, &upstream, Protocol::Tcp, no_aging());

        let message = parse(&out);
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert!(message.edns.is_none());
    }

    #[test]
    fn no_extended_rcode_stays_a_plain_header_rcode() {
        let upstream = reply_with_extended_rcode(0);
        let mut client = QuerySpec::new("example.com.", RecordType::A);
        client.edns = Some((1232, false));

        let out = from_upstream(&client, &upstream, Protocol::Udp, no_aging());

        assert_eq!(parse(&out).metadata.response_code, ResponseCode::NoError);
    }

    #[test]
    fn a_truncated_upstream_reply_stays_truncated_over_tcp_and_udp() {
        let client = QuerySpec::new("example.com.", RecordType::A);
        let mut upstream = ResponseSpec {
            answers: vec![a("example.com.", 120, [192, 0, 2, 1].into())],
            ..ResponseSpec::default()
        }
        .bytes(&client);
        upstream[2] |= 0x02;

        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let out = from_upstream(&client, &upstream, protocol, no_aging());

            let message = parse(&out);
            assert!(message.metadata.truncation, "{protocol:?}");
            assert_eq!(message.answers.len(), 1, "{protocol:?}");
        }
    }

    #[test]
    fn a_stored_reply_without_the_question_becomes_servfail() {
        let client = QuerySpec::new("example.com.", RecordType::A);

        let out = from_upstream_with_garbage(&client, &[0; 12]);

        assert_eq!(parse(&out).metadata.response_code, ResponseCode::ServFail);
    }

    fn from_upstream_with_garbage(spec: &QuerySpec, upstream: &[u8]) -> Vec<u8> {
        let bytes = spec.bytes();
        let query = Query::parse(&bytes).unwrap();
        let parts = ReplyParts {
            bytes: upstream,
            ttl_offsets: &[],
            opt_start: None,
        };
        let mut out = Vec::new();

        Reply::new(&query, SERVER_UDP_SIZE, Protocol::Udp).from_upstream(
            parts,
            no_aging(),
            &mut out,
        );

        out
    }

    #[test]
    fn a_compact_query_keeps_what_the_reply_needs_and_drops_the_rest() {
        let mut client = QuerySpec::new("WWW.Example.COM.", RecordType::AAAA);
        client.id = 0x4242;
        client.checking_disabled = true;
        client.edns = Some((1400, true));
        let mut bytes = client.bytes();
        let rdata_length_at = bytes.len() - 2;
        bytes[rdata_length_at..].copy_from_slice(&5000u16.to_be_bytes());
        bytes.resize(bytes.len() + 5000, 0);
        let query = Query::parse(&bytes).unwrap();

        let compact = compact_query(&query);

        assert_eq!(compact.capacity(), compact.len());
        assert!(compact.len() < 64, "{} bytes", compact.len());
        let again = Query::parse(&compact).unwrap();
        assert_eq!(again.id(), 0x4242);
        assert_eq!(again.header.flags, query.header.flags);
        assert_eq!(again.question_bytes(), query.question_bytes());
        assert_eq!(
            again.edns,
            Some(crate::dns::wire::Edns {
                udp_size: 1400,
                dnssec_ok: true
            })
        );
        let without_edns = QuerySpec::new("example.com.", RecordType::A).bytes();
        let plain = compact_query(&Query::parse(&without_edns).unwrap());
        assert_eq!(Query::parse(&plain).unwrap().edns, None);
    }

    #[test]
    fn upstream_query_is_normalized() {
        let mut client = QuerySpec::new("WWW.Example.COM.", RecordType::AAAA);
        client.id = 0x4242;
        client.checking_disabled = true;
        client.recursion_desired = false;
        client.edns = Some((512, true));
        let bytes = client.bytes();
        let query = Query::parse(&bytes).unwrap();

        let out = upstream_query(&query, SERVER_UDP_SIZE);

        let message = parse(&out);
        assert_eq!(message.metadata.id, 0);
        assert!(!message.metadata.recursion_desired);
        assert!(message.metadata.checking_disabled);
        assert_eq!(message.queries[0].name().to_ascii(), "www.example.com.");
        assert_eq!(message.queries[0].query_type(), RecordType::AAAA);
        let edns = message.edns.unwrap();
        assert_eq!(edns.max_payload(), SERVER_UDP_SIZE);
        assert!(edns.flags().dnssec_ok);
        assert!(edns.options().as_ref().is_empty());
    }

    #[test]
    fn upstream_query_always_has_opt_and_drops_client_options() {
        let client = QuerySpec::new("example.com.", RecordType::A);
        let bytes = client.bytes();
        let query = Query::parse(&bytes).unwrap();

        let out = upstream_query(&query, SERVER_UDP_SIZE);

        let message = parse(&out);
        assert!(message.metadata.recursion_desired);
        assert!(!message.edns.unwrap().flags().dnssec_ok);
        assert_eq!(out.len(), HEADER_LEN + 13 + 4 + OPT_RECORD_LEN);
    }
}
