use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

pub const HEADER_LEN: usize = 12;
pub const MAX_NAME_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
/// The largest DNS message: the 16-bit length of a TCP frame.
pub const MAX_MESSAGE_LEN: usize = 65535;

pub mod rtype {
    pub const A: u16 = 1;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const AAAA: u16 = 28;
    pub const OPT: u16 = 41;
    pub const HTTPS: u16 = 65;
    pub const ANY: u16 = 255;
}

pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const FORMERR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;
}

pub const CLASS_IN: u16 = 1;

pub mod flags {
    pub const QR: u16 = 0x8000;
    pub const OPCODE_MASK: u16 = 0x7800;
    pub const AA: u16 = 0x0400;
    pub const TC: u16 = 0x0200;
    pub const RD: u16 = 0x0100;
    pub const RA: u16 = 0x0080;
    pub const AD: u16 = 0x0020;
    pub const CD: u16 = 0x0010;
    pub const RCODE_MASK: u16 = 0x000F;
}

const EDNS_DO: u32 = 0x8000;
const SVCB_KEY_IPV4_HINT: u16 = 4;
const SVCB_KEY_IPV6_HINT: u16 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadName,
    Malformed,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => {
                write!(formatter, "message is truncated")
            }

            WireError::BadName => {
                write!(formatter, "invalid domain name")
            }

            WireError::Malformed => {
                write!(formatter, "malformed message")
            }
        }
    }
}

impl std::error::Error for WireError {}

fn read_u16(msg: &[u8], at: usize) -> Result<u16, WireError> {
    let bytes = msg.get(at..at + 2).ok_or(WireError::Truncated)?;

    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(msg: &[u8], at: usize) -> Result<u32, WireError> {
    let bytes = msg.get(at..at + 4).ok_or(WireError::Truncated)?;

    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl Header {
    pub fn parse(msg: &[u8]) -> Result<Header, WireError> {
        if msg.len() < HEADER_LEN {
            return Err(WireError::Truncated);
        }

        Ok(Header {
            id: read_u16(msg, 0)?,
            flags: read_u16(msg, 2)?,
            question_count: read_u16(msg, 4)?,
            answer_count: read_u16(msg, 6)?,
            authority_count: read_u16(msg, 8)?,
            additional_count: read_u16(msg, 10)?,
        })
    }

    pub fn is_response(&self) -> bool {
        self.flags & flags::QR != 0
    }

    pub fn opcode(&self) -> u8 {
        ((self.flags & flags::OPCODE_MASK) >> 11) as u8
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & flags::RCODE_MASK) as u8
    }

    pub fn recursion_desired(&self) -> bool {
        self.flags & flags::RD != 0
    }

    pub fn checking_disabled(&self) -> bool {
        self.flags & flags::CD != 0
    }

    pub fn truncated(&self) -> bool {
        self.flags & flags::TC != 0
    }
}

/// A domain name in uncompressed wire format with ASCII letters lowercased.
#[derive(Clone)]
pub struct Name {
    bytes: [u8; MAX_NAME_LEN],
    len: u8,
}

impl Name {
    fn empty() -> Name {
        Name {
            bytes: [0; MAX_NAME_LEN],
            len: 0,
        }
    }

    pub fn root() -> Name {
        let mut name = Name::empty();
        name.push_terminator();

        name
    }

    /// Parses dotted text such as `home.arpa.`. No escapes, no empty labels.
    pub fn from_text(text: &str) -> Option<Name> {
        let trimmed = text.strip_suffix('.').unwrap_or(text);
        let mut name = Name::empty();

        if !trimmed.is_empty() {
            for label in trimmed.split('.') {
                if label.is_empty() || label.len() > MAX_LABEL_LEN || !label.is_ascii() {
                    return None;
                }

                name.push_label(label.as_bytes()).ok()?;
            }
        }

        name.push_terminator();

        Some(name)
    }

    fn push_label(&mut self, label: &[u8]) -> Result<(), WireError> {
        let start = usize::from(self.len);

        // One byte stays reserved for the terminating zero label.
        if start + 1 + label.len() + 1 > MAX_NAME_LEN {
            return Err(WireError::BadName);
        }

        self.bytes[start] = label.len() as u8;
        for (target, byte) in self.bytes[start + 1..].iter_mut().zip(label) {
            *target = byte.to_ascii_lowercase();
        }

        self.len += 1 + label.len() as u8;

        Ok(())
    }

    fn push_terminator(&mut self) {
        self.bytes[usize::from(self.len)] = 0;
        self.len += 1;
    }

    pub fn as_wire(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub fn is_root(&self) -> bool {
        self.len == 1
    }

    /// The labels from left to right, without the terminating zero label.
    pub fn labels(&self) -> Labels<'_> {
        Labels {
            remaining: self.as_wire(),
        }
    }

    /// True when `self` equals `ancestor` or lies below it.
    pub fn is_subdomain_of(&self, ancestor: &Name) -> bool {
        let wire = self.as_wire();
        let ancestor_wire = ancestor.as_wire();
        let mut start = 0;

        while start < wire.len() {
            if &wire[start..] == ancestor_wire {
                return true;
            }

            start += 1 + usize::from(wire[start]);
        }

        false
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.as_wire() == other.as_wire()
    }
}

impl Eq for Name {}

impl fmt::Debug for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Name({self})")
    }
}

/// Dotted text without the trailing dot; the root is ".".
impl fmt::Display for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return write!(formatter, ".");
        }

        for (index, label) in self.labels().enumerate() {
            if index > 0 {
                write!(formatter, ".")?;
            }

            for &byte in label {
                match byte {
                    b'.' | b'\\' => {
                        write!(formatter, "\\{}", byte as char)?;
                    }

                    0x21..=0x7e => {
                        write!(formatter, "{}", byte as char)?;
                    }

                    _ => {
                        write!(formatter, "\\{byte:03}")?;
                    }
                }
            }
        }

        Ok(())
    }
}

pub struct Labels<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(*self.remaining.first()?);
        if length == 0 {
            return None;
        }

        let label = &self.remaining[1..1 + length];
        self.remaining = &self.remaining[1 + length..];

        Some(label)
    }
}

/// A name reached through at most this many compression pointers is accepted;
/// real messages use one or two.
const MAX_NAME_POINTERS: usize = 128;

/// Where a name written at some offset ends.
struct NameSpan {
    /// The offset after the name as written, where the next field begins.
    end: usize,
    /// The offset of the pointer that ends the name, if it is compressed.
    pointer_at: Option<usize>,
}

/// The one walker over names, for decompression, skipping and validation.
/// Follows compression pointers, which must point strictly backward and at
/// most `MAX_NAME_POINTERS` times, and fails when the expanded name passes
/// 255 bytes, so no input can make it loop. Calls `on_label` for every label
/// of the expanded name.
fn walk_name<F>(msg: &[u8], start: usize, mut on_label: F) -> Result<NameSpan, WireError>
where
    F: FnMut(&[u8]) -> Result<(), WireError>,
{
    let mut position = start;
    let mut end = None;
    let mut pointer_at = None;
    let mut pointers = 0;
    // The terminating zero label.
    let mut expanded_len = 1;

    loop {
        let first = *msg.get(position).ok_or(WireError::Truncated)?;

        match first & 0xC0 {
            0x00 => {
                let length = usize::from(first);
                if length == 0 {
                    return Ok(NameSpan {
                        end: end.unwrap_or(position + 1),
                        pointer_at,
                    });
                }

                expanded_len += 1 + length;
                if expanded_len > MAX_NAME_LEN {
                    return Err(WireError::BadName);
                }

                let label = msg
                    .get(position + 1..position + 1 + length)
                    .ok_or(WireError::Truncated)?;
                on_label(label)?;
                position += 1 + length;
            }

            0xC0 => {
                let second = *msg.get(position + 1).ok_or(WireError::Truncated)?;
                let target = (usize::from(first & 0x3F) << 8) | usize::from(second);
                if end.is_none() {
                    end = Some(position + 2);
                    pointer_at = Some(position);
                }

                pointers += 1;
                if target >= position || pointers > MAX_NAME_POINTERS {
                    return Err(WireError::BadName);
                }

                position = target;
            }

            _ => {
                return Err(WireError::BadName);
            }
        }
    }
}

/// Reads the name at `start`, following compression pointers. Returns the
/// lowercased name and the offset just after it in the original position.
pub fn read_name(msg: &[u8], start: usize) -> Result<(Name, usize), WireError> {
    let mut name = Name::empty();
    let end = walk_name(msg, start, |label| name.push_label(label))?.end;
    name.push_terminator();

    Ok((name, end))
}

/// Returns the offset just after the name at `start`. The name is walked
/// without being kept, so a bad pointer is an error here too.
pub fn skip_name(msg: &[u8], start: usize) -> Result<usize, WireError> {
    Ok(walk_name(msg, start, |_| Ok(()))?.end)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub qclass: u16,
}

fn read_question(msg: &[u8], start: usize) -> Result<(Question, usize), WireError> {
    let (name, after_name) = read_name(msg, start)?;
    let qtype = read_u16(msg, after_name)?;
    let qclass = read_u16(msg, after_name + 2)?;

    Ok((
        Question {
            name,
            qtype,
            qclass,
        },
        after_name + 4,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edns {
    pub udp_size: u16,
    pub dnssec_ok: bool,
}

/// Why a datagram or frame is not a query that can be processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryError {
    /// Not worth an answer: too short for a header, or a response.
    Drop,
    /// Answer with only a header carrying this rcode.
    Reject { header: Header, rcode: u8 },
}

/// A client query borrowed from its packet.
#[derive(Debug)]
pub struct Query<'a> {
    raw: &'a [u8],
    pub header: Header,
    pub question: Question,
    question_end: usize,
    pub edns: Option<Edns>,
}

impl<'a> Query<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Query<'a>, QueryError> {
        let header = Header::parse(raw).map_err(|_| QueryError::Drop)?;
        if header.is_response() {
            return Err(QueryError::Drop);
        }

        let reject = |rcode| QueryError::Reject { header, rcode };

        if header.opcode() != 0 {
            return Err(reject(rcode::NOTIMP));
        }

        if header.question_count != 1 || header.answer_count != 0 || header.authority_count != 0 {
            return Err(reject(rcode::FORMERR));
        }

        let (question, question_end) =
            read_question(raw, HEADER_LEN).map_err(|_| reject(rcode::FORMERR))?;
        let edns = read_query_edns(raw, question_end, header.additional_count)
            .map_err(|_| reject(rcode::FORMERR))?;

        Ok(Query {
            raw,
            header,
            question,
            question_end,
            edns,
        })
    }

    pub fn id(&self) -> u16 {
        self.header.id
    }

    /// The question exactly as the client sent it, keeping its letter case.
    pub fn question_bytes(&self) -> &'a [u8] {
        &self.raw[HEADER_LEN..self.question_end]
    }

    pub fn dnssec_ok(&self) -> bool {
        self.edns.is_some_and(|edns| edns.dnssec_ok)
    }
}

fn read_query_edns(msg: &[u8], start: usize, count: u16) -> Result<Option<Edns>, WireError> {
    let mut position = start;
    let mut edns = None;

    for _ in 0..count {
        let name_end = skip_name(msg, position)?;
        let rtype = read_u16(msg, name_end)?;
        let class = read_u16(msg, name_end + 2)?;
        let ttl = read_u32(msg, name_end + 4)?;
        let rdata_length = usize::from(read_u16(msg, name_end + 8)?);
        let end = name_end + 10 + rdata_length;
        if end > msg.len() {
            return Err(WireError::Truncated);
        }

        if rtype == rtype::OPT {
            if edns.is_some() || name_end != position + 1 {
                return Err(WireError::Malformed);
            }

            edns = Some(Edns {
                udp_size: class,
                dnssec_ok: ttl & EDNS_DO != 0,
            });
        }

        position = end;
    }

    Ok(edns)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub section: Section,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    /// Offset of the owner name.
    pub start: usize,
    pub ttl_offset: usize,
    pub rdata: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Box<Name>),
    Soa { minimum: u32 },
    Https(AddressHints<'a>),
    Other,
}

impl Record {
    /// Decodes the record data types a filter or cache cares about.
    pub fn data<'a>(&self, msg: &'a [u8]) -> Result<RData<'a>, WireError> {
        let rdata = &msg[self.rdata.clone()];

        match self.rtype {
            rtype::A => {
                let octets: [u8; 4] = rdata.try_into().map_err(|_| WireError::Malformed)?;

                return Ok(RData::A(octets.into()));
            }

            rtype::AAAA => {
                let octets: [u8; 16] = rdata.try_into().map_err(|_| WireError::Malformed)?;

                return Ok(RData::Aaaa(octets.into()));
            }

            rtype::CNAME => {
                let (name, end) = read_name(msg, self.rdata.start)?;
                if end != self.rdata.end {
                    return Err(WireError::Malformed);
                }

                return Ok(RData::Cname(Box::new(name)));
            }

            rtype::SOA => {
                let after_mname = skip_name(msg, self.rdata.start)?;
                let after_rname = skip_name(msg, after_mname)?;
                if after_rname + 20 != self.rdata.end {
                    return Err(WireError::Malformed);
                }

                return Ok(RData::Soa {
                    minimum: read_u32(msg, after_rname + 16)?,
                });
            }

            rtype::HTTPS => {
                let after_target = skip_name(msg, self.rdata.start + 2)?;
                if after_target > self.rdata.end {
                    return Err(WireError::Malformed);
                }

                return Ok(RData::Https(AddressHints {
                    params: &msg[after_target..self.rdata.end],
                    current: &[],
                    current_is_ipv6: false,
                }));
            }

            _ => {}
        }

        Ok(RData::Other)
    }
}

/// The `ipv4hint` and `ipv6hint` addresses of an HTTPS record. Stops quietly at
/// malformed service parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressHints<'a> {
    params: &'a [u8],
    current: &'a [u8],
    current_is_ipv6: bool,
}

impl Iterator for AddressHints<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        loop {
            let address_length = if self.current_is_ipv6 { 16 } else { 4 };

            if self.current.len() >= address_length {
                let (address, rest) = self.current.split_at(address_length);
                self.current = rest;

                return Some(if self.current_is_ipv6 {
                    IpAddr::V6(<[u8; 16]>::try_from(address).ok()?.into())
                } else {
                    IpAddr::V4(<[u8; 4]>::try_from(address).ok()?.into())
                });
            }

            let key = read_u16(self.params, 0).ok()?;
            let length = usize::from(read_u16(self.params, 2).ok()?);
            let value = self.params.get(4..4 + length)?;
            self.params = &self.params[4 + length..];

            self.current = &[];
            if key == SVCB_KEY_IPV4_HINT {
                self.current = value;
                self.current_is_ipv6 = false;
            } else if key == SVCB_KEY_IPV6_HINT {
                self.current = value;
                self.current_is_ipv6 = true;
            }
        }
    }
}

/// Walks every resource record after the question section.
pub struct Records<'a> {
    msg: &'a [u8],
    position: usize,
    remaining: [u16; 3],
    failed: bool,
}

impl<'a> Records<'a> {
    pub fn new(msg: &'a [u8]) -> Result<Records<'a>, WireError> {
        let header = Header::parse(msg)?;
        let mut position = HEADER_LEN;

        for _ in 0..header.question_count {
            position = skip_name(msg, position)? + 4;
        }

        if position > msg.len() {
            return Err(WireError::Truncated);
        }

        Ok(Records {
            msg,
            position,
            remaining: [
                header.answer_count,
                header.authority_count,
                header.additional_count,
            ],
            failed: false,
        })
    }

    fn read_record(&mut self, section: Section) -> Result<Record, WireError> {
        let start = self.position;
        let name_end = skip_name(self.msg, start)?;
        let rtype = read_u16(self.msg, name_end)?;
        let class = read_u16(self.msg, name_end + 2)?;
        let ttl = read_u32(self.msg, name_end + 4)?;
        let rdata_length = usize::from(read_u16(self.msg, name_end + 8)?);
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start + rdata_length;
        if rdata_end > self.msg.len() {
            return Err(WireError::Truncated);
        }

        self.position = rdata_end;

        Ok(Record {
            section,
            rtype,
            class,
            ttl,
            start,
            ttl_offset: name_end + 4,
            rdata: rdata_start..rdata_end,
        })
    }
}

impl Iterator for Records<'_> {
    type Item = Result<Record, WireError>;

    fn next(&mut self) -> Option<Result<Record, WireError>> {
        if self.failed {
            return None;
        }

        let section = if self.remaining[0] > 0 {
            self.remaining[0] -= 1;
            Section::Answer
        } else if self.remaining[1] > 0 {
            self.remaining[1] -= 1;
            Section::Authority
        } else if self.remaining[2] > 0 {
            self.remaining[2] -= 1;
            Section::Additional
        } else {
            return None;
        };

        let record = self.read_record(section);
        self.failed = record.is_err();

        Some(record)
    }
}

/// What the cache and the reply builder need to know about an upstream reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseInfo {
    pub header: Header,
    /// Offsets of the TTL field of every record except OPT.
    pub ttl_offsets: Vec<u16>,
    /// Offset of the OPT record, which may be anywhere in the additional
    /// section.
    pub opt_start: Option<u16>,
    /// Smallest TTL over all records except OPT.
    pub min_ttl: Option<u32>,
    /// RFC 2308 negative TTL: smallest of the authority SOA's TTL and minimum.
    pub negative_ttl: Option<u32>,
    /// NXDOMAIN, or NOERROR where the name at the end of the answer's CNAME
    /// chain (the queried name when there is no chain) has no data.
    pub is_negative: bool,
    /// The upper 8 bits of the 12-bit RCODE, from the OPT record (0 without
    /// one).
    pub extended_rcode: u8,
    soas: Vec<AuthoritySoa>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthoritySoa {
    ttl_offset: u16,
    minimum: u32,
}

impl ResponseInfo {
    pub fn parse(msg: &[u8]) -> Result<ResponseInfo, WireError> {
        if msg.len() > MAX_MESSAGE_LEN {
            return Err(WireError::Malformed);
        }

        let header = Header::parse(msg)?;
        let mut info = ResponseInfo {
            header,
            ttl_offsets: Vec::new(),
            opt_start: None,
            min_ttl: None,
            negative_ttl: None,
            is_negative: false,
            extended_rcode: 0,
            soas: Vec::new(),
        };

        for record in Records::new(msg)? {
            let record = record?;

            if record.rtype == rtype::OPT {
                let has_root_owner = record.ttl_offset == record.start + 1 + 4;
                if record.section != Section::Additional
                    || info.opt_start.is_some()
                    || !has_root_owner
                {
                    return Err(WireError::Malformed);
                }

                info.opt_start = Some(offset(record.start)?);
                info.extended_rcode = (record.ttl >> 24) as u8;

                continue;
            }

            info.ttl_offsets.push(offset(record.ttl_offset)?);
            info.min_ttl = Some(info.min_ttl.map_or(record.ttl, |min| min.min(record.ttl)));

            if record.section == Section::Authority
                && let RData::Soa { minimum } = record.data(msg)?
            {
                let ttl = record.ttl.min(minimum);
                info.negative_ttl = Some(info.negative_ttl.map_or(ttl, |min| min.min(ttl)));
                info.soas.push(AuthoritySoa {
                    ttl_offset: offset(record.ttl_offset)?,
                    minimum,
                });
            }
        }

        info.is_negative = is_negative(msg, &header)?;

        Ok(info)
    }
}

impl ResponseInfo {
    /// RFC 2308 section 5: in a negative reply the TTL of the SOA is the smaller
    /// of its own TTL and its MINIMUM. Writing that into `msg` as the reply
    /// arrives makes the SOA TTL clients see age together with the lifetime
    /// the cache gives the reply. `msg` must be the bytes this was parsed from.
    pub fn cap_soa_ttls(&mut self, msg: &mut [u8]) {
        if !self.is_negative {
            return;
        }

        for soa in &self.soas {
            let at = usize::from(soa.ttl_offset);
            let Ok(ttl) = read_u32(msg, at) else {
                continue;
            };

            let capped = ttl.min(soa.minimum);

            msg[at..at + 4].copy_from_slice(&capped.to_be_bytes());
            self.min_ttl = Some(self.min_ttl.map_or(capped, |min| min.min(capped)));
        }
    }
}

/// A CNAME chain this long is not followed further; it is left unclassified
/// rather than called empty.
const MAX_CNAME_HOPS: usize = 8;

fn is_negative(msg: &[u8], header: &Header) -> Result<bool, WireError> {
    match header.rcode() {
        rcode::NXDOMAIN => {
            return Ok(true);
        }

        rcode::NOERROR => {}

        _ => {
            return Ok(false);
        }
    }

    if header.answer_count == 0 {
        return Ok(true);
    }

    if header.question_count != 1 {
        return Ok(false);
    }

    let (question, _) = read_question(msg, HEADER_LEN)?;
    if question.qtype == rtype::CNAME || question.qtype == rtype::ANY {
        return Ok(false);
    }

    let mut current = question.name;
    let mut reached_the_end = false;
    for _ in 0..MAX_CNAME_HOPS {
        let Some(target) = cname_target_of(msg, &current)? else {
            reached_the_end = true;

            break;
        };

        current = target;
    }

    Ok(reached_the_end && !has_answer_for(msg, &current)?)
}

fn answers(msg: &[u8]) -> Result<impl Iterator<Item = Result<Record, WireError>>, WireError> {
    Ok(Records::new(msg)?.take_while(|record| {
        record
            .as_ref()
            .map_or(true, |record| record.section == Section::Answer)
    }))
}

fn cname_target_of(msg: &[u8], owner: &Name) -> Result<Option<Name>, WireError> {
    for record in answers(msg)? {
        let record = record?;
        if record.rtype == rtype::CNAME
            && read_name(msg, record.start)?.0 == *owner
            && let RData::Cname(target) = record.data(msg)?
        {
            return Ok(Some(*target));
        }
    }

    Ok(None)
}

fn has_answer_for(msg: &[u8], owner: &Name) -> Result<bool, WireError> {
    for record in answers(msg)? {
        if read_name(msg, record?.start)?.0 == *owner {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Types whose rdata RFC 1035 lets a server compress (RFC 3597 section 4
/// forbids it for every other type): one domain name first.
const NAME_FIRST_TYPES: [u16; 8] = [2, 3, 4, 5, 7, 8, 9, 12];
/// Two domain names: SOA, MINFO and RP.
const TWO_NAMES_TYPES: [u16; 3] = [6, 14, 17];
/// A 16-bit preference, then a domain name: MX, AFSDB and RT.
const PREFERENCE_THEN_NAME_TYPES: [u16; 3] = [15, 18, 21];

/// Removes the OPT record at `opt_start` and moves what follows it up, so a
/// reply can carry our OPT instead of the upstream's, whichever place in the
/// additional section the upstream gave it. The compression pointers of the
/// records after it are lowered by the OPT's length. Fails if one of them
/// points into the OPT.
pub fn remove_opt(msg: &mut Vec<u8>, opt_start: usize) -> Result<(), WireError> {
    let records: Vec<Record> = Records::new(msg)?.collect::<Result<_, _>>()?;
    let opt = records
        .iter()
        .find(|record| record.start == opt_start && record.rtype == rtype::OPT)
        .ok_or(WireError::Malformed)?;
    let opt_end = opt.rdata.end;
    let removed = opt_end - opt_start;

    let mut pointers = Vec::new();
    for record in records.iter().filter(|record| record.start >= opt_end) {
        compression_pointers(msg, record, &mut pointers)?;
    }

    for at in pointers {
        let target = (usize::from(msg[at] & 0x3F) << 8) | usize::from(msg[at + 1]);
        if (opt_start..opt_end).contains(&target) {
            return Err(WireError::BadName);
        }

        if target >= opt_end {
            let moved = target - removed;
            msg[at] = 0xC0 | (moved >> 8) as u8;
            msg[at + 1] = moved as u8;
        }
    }

    msg.drain(opt_start..opt_end);
    let additional = read_u16(msg, 10)?.saturating_sub(1);
    msg[10..12].copy_from_slice(&additional.to_be_bytes());

    Ok(())
}

/// The offsets of the compression pointers written in the owner name and in
/// the rdata names of `record`.
fn compression_pointers(
    msg: &[u8],
    record: &Record,
    pointers: &mut Vec<usize>,
) -> Result<(), WireError> {
    pointers.extend(walk_name(msg, record.start, |_| Ok(()))?.pointer_at);

    let (mut name_at, name_count) = if NAME_FIRST_TYPES.contains(&record.rtype) {
        (record.rdata.start, 1)
    } else if TWO_NAMES_TYPES.contains(&record.rtype) {
        (record.rdata.start, 2)
    } else if PREFERENCE_THEN_NAME_TYPES.contains(&record.rtype) {
        (record.rdata.start + 2, 1)
    } else {
        return Ok(());
    };

    for _ in 0..name_count {
        let name = walk_name(msg, name_at, |_| Ok(()))?;
        if name.end > record.rdata.end {
            return Err(WireError::Malformed);
        }

        pointers.extend(name.pointer_at);
        name_at = name.end;
    }

    Ok(())
}

fn offset(position: usize) -> Result<u16, WireError> {
    u16::try_from(position).map_err(|_| WireError::Malformed)
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::Message;
    use hickory_proto::rr::{RData as OracleRData, RecordType};
    use proptest::prelude::*;

    use super::*;
    use crate::dns::test_util::{
        OPT_BEFORE_ADDITIONALS_FIRST_START, OPT_BEFORE_ADDITIONALS_OPT_START, QuerySpec,
        ResponseSpec, a, aaaa, cname, https, parse as parse_with_oracle,
        response_with_opt_before_other_additionals, soa,
    };

    fn ttl_at(msg: &[u8], offset: u16) -> u32 {
        read_u32(msg, usize::from(offset)).unwrap()
    }

    fn name_of(text: &str) -> Name {
        Name::from_text(text).unwrap()
    }

    #[test]
    fn query_fields_match_the_oracle() {
        let mut spec = QuerySpec::new("Www.Example.com.", RecordType::AAAA);
        spec.id = 0xBEEF;
        spec.checking_disabled = true;
        spec.edns = Some((1400, true));
        let bytes = spec.bytes();

        let query = Query::parse(&bytes).unwrap();

        let oracle = parse_with_oracle(&bytes);
        assert_eq!(query.id(), oracle.metadata.id);
        assert_eq!(
            query.header.recursion_desired(),
            oracle.metadata.recursion_desired
        );
        assert_eq!(
            query.header.checking_disabled(),
            oracle.metadata.checking_disabled
        );
        assert_eq!(
            query.question.qtype,
            u16::from(oracle.queries[0].query_type())
        );
        assert_eq!(query.question.qclass, CLASS_IN);
        assert_eq!(query.question.name.to_string(), "www.example.com");
        assert_eq!(
            query.edns,
            Some(Edns {
                udp_size: 1400,
                dnssec_ok: true
            })
        );
    }

    #[test]
    fn query_without_edns_has_no_edns_and_no_dnssec_ok() {
        let bytes = QuerySpec::new("example.com.", RecordType::A).bytes();

        let query = Query::parse(&bytes).unwrap();

        assert_eq!(query.edns, None);
        assert!(!query.dnssec_ok());
    }

    #[test]
    fn question_bytes_keep_the_clients_letter_case() {
        let bytes = QuerySpec::new("ExAmPle.COM.", RecordType::A).bytes();

        let query = Query::parse(&bytes).unwrap();

        assert_eq!(
            query.question_bytes(),
            &bytes[HEADER_LEN..HEADER_LEN + 13 + 4]
        );
        assert_eq!(&query.question_bytes()[1..8], b"ExAmPle");
        assert_eq!(query.question.name.as_wire(), b"\x07example\x03com\x00");
    }

    #[test]
    fn short_packets_and_responses_are_dropped() {
        let mut response = QuerySpec::new("example.com.", RecordType::A).bytes();
        response[2] |= 0x80;

        assert_eq!(Query::parse(&[]).unwrap_err(), QueryError::Drop);
        assert_eq!(Query::parse(&[0; 11]).unwrap_err(), QueryError::Drop);
        assert_eq!(Query::parse(&response).unwrap_err(), QueryError::Drop);
    }

    #[test]
    fn malformed_queries_are_rejected_with_the_id_and_a_reason() {
        let good = QuerySpec::new("example.com.", RecordType::A).bytes();

        let mut other_opcode = good.clone();
        other_opcode[2] |= 4 << 3;
        let mut no_question = good.clone();
        no_question[5] = 0;
        let mut two_questions = good.clone();
        two_questions[5] = 2;
        let mut with_answer = good.clone();
        with_answer[7] = 1;
        let truncated_question = good[..HEADER_LEN + 5].to_vec();
        let cases = [
            (other_opcode, rcode::NOTIMP),
            (no_question, rcode::FORMERR),
            (two_questions, rcode::FORMERR),
            (with_answer, rcode::FORMERR),
            (truncated_question, rcode::FORMERR),
        ];

        for (bytes, expected) in cases {
            match Query::parse(&bytes) {
                Err(QueryError::Reject { header, rcode }) => {
                    assert_eq!(header.id, 0x1234);
                    assert_eq!(rcode, expected);
                }

                other => panic!("expected a rejection, got {other:?}"),
            }
        }
    }

    #[test]
    fn query_with_two_opt_records_or_a_named_opt_is_rejected() {
        let mut spec = QuerySpec::new("example.com.", RecordType::A);
        spec.edns = Some((1232, false));
        let good = spec.bytes();
        let opt = good[good.len() - 11..].to_vec();
        let mut two_opts = good.clone();
        two_opts.extend_from_slice(&opt);
        two_opts[11] = 2;
        let mut named_opt = good.clone();
        let opt_start = good.len() - 11;
        named_opt.splice(opt_start..opt_start + 1, [1, b'x', 0]);

        for bytes in [two_opts, named_opt] {
            assert!(matches!(
                Query::parse(&bytes),
                Err(QueryError::Reject {
                    rcode: rcode::FORMERR,
                    ..
                })
            ));
        }
    }

    #[test]
    fn names_decompress_and_lowercase() {
        let mut msg = vec![0; HEADER_LEN];
        msg.extend_from_slice(b"\x03WWW\x07Example\x03COM\x00");
        let pointer_at = msg.len();
        msg.extend_from_slice(&[3, b'f', b't', b'p', 0xC0, HEADER_LEN as u8 + 4]);

        let (name, end) = read_name(&msg, pointer_at).unwrap();

        assert_eq!(name.to_string(), "ftp.example.com");
        assert_eq!(end, msg.len());
        assert_eq!(skip_name(&msg, pointer_at).unwrap(), msg.len());
    }

    #[test]
    fn pointer_loops_and_forward_pointers_are_rejected() {
        let self_pointer = [0xC0, 0x00];
        let forward = [0xC0, 0x04, 0, 0, 1, b'a', 0];
        // The label chain at 0 runs into a pointer back to 0.
        let cycle_through_labels = [1, b'a', 0xC0, 0x00];
        let mut pointer_to_pointer = vec![0; 2];
        pointer_to_pointer.extend_from_slice(&[0xC0, 0x02]);

        assert_eq!(read_name(&self_pointer, 0), Err(WireError::BadName));
        assert_eq!(read_name(&forward, 0), Err(WireError::BadName));
        assert_eq!(read_name(&cycle_through_labels, 0), Err(WireError::BadName));
        assert_eq!(read_name(&pointer_to_pointer, 2), Err(WireError::BadName));
    }

    #[test]
    fn a_pointer_cycle_that_walks_labels_ends_at_the_name_limit() {
        // Offset 0: label "a" then a pointer at 2 that jumps back to 0.
        // Backward-only pointers allow this; the length limit must stop it.
        let msg = [1, b'a', 0xC0, 0x00, 0, 0];

        let result = read_name(&msg, 2);

        assert_eq!(result, Err(WireError::BadName));
    }

    fn pointer_to(target: usize) -> [u8; 2] {
        [0xC0 | (target >> 8) as u8, target as u8]
    }

    /// A response with the given question name and one record per `(owner,
    /// rtype, rdata)`; every record is class IN with TTL 60.
    fn response_of(question_name: &[u8], records: &[(&[u8], u16, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![
            0x12,
            0x34,
            0x81,
            0x80,
            0,
            1,
            0,
            records.len() as u8,
            0,
            0,
            0,
            0,
        ];
        bytes.extend_from_slice(question_name);
        bytes.extend_from_slice(&[0, 1, 0, 1]);

        for (owner, rtype, rdata) in records {
            bytes.extend_from_slice(owner);
            bytes.extend_from_slice(&rtype.to_be_bytes());
            bytes.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            bytes.extend_from_slice(rdata);
        }

        bytes
    }

    const EXAMPLE_COM: &[u8] = b"\x07example\x03com\x00";
    const A_RDATA: &[u8] = &[192, 0, 2, 1];

    fn owner_offset(question_name: &[u8]) -> usize {
        HEADER_LEN + question_name.len() + 4
    }

    #[test]
    fn a_response_with_a_good_compressed_owner_name_parses() {
        let owner = pointer_to(HEADER_LEN);

        let info = ResponseInfo::parse(&response_of(EXAMPLE_COM, &[(&owner, 1, A_RDATA)])).unwrap();

        assert_eq!(info.ttl_offsets.len(), 1);
    }

    #[test]
    fn response_owner_names_with_bad_pointers_are_rejected_not_skipped() {
        let at = owner_offset(EXAMPLE_COM);
        let with_owner = |owner: &[u8]| response_of(EXAMPLE_COM, &[(owner, 1, A_RDATA)]);
        let cases = [
            ("pointer to itself", with_owner(&pointer_to(at))),
            ("pointer forward", with_owner(&pointer_to(at + 2))),
            ("pointer past the message", with_owner(&pointer_to(9000))),
            (
                "label, then a pointer back to the label",
                with_owner(&[1, b'a', pointer_to(at)[0], pointer_to(at)[1]]),
            ),
            ("reserved label type", with_owner(&[0x40, 0])),
        ];

        for (label, bytes) in cases {
            assert!(ResponseInfo::parse(&bytes).is_err(), "{label}");
        }
    }

    #[test]
    fn an_owner_name_that_expands_past_255_bytes_is_rejected() {
        let mut long_question = Vec::new();
        for _ in 0..4 {
            long_question.push(50);
            long_question.extend_from_slice(&[b'a'; 50]);
        }

        long_question.push(0);
        let mut owner = vec![60];
        owner.extend_from_slice(&[b'b'; 60]);
        owner.extend_from_slice(&pointer_to(HEADER_LEN));

        let bytes = response_of(&long_question, &[(&owner, 1, A_RDATA)]);

        assert_eq!(ResponseInfo::parse(&bytes), Err(WireError::BadName));
    }

    #[test]
    fn a_chain_of_pointers_beyond_the_limit_is_rejected() {
        // Record 1 carries 200 pointers, each aimed at the one before it, in
        // opaque rdata. Record 2's owner points at the last of them.
        let rdata_start = owner_offset(EXAMPLE_COM) + 2 + 2 + 2 + 4 + 2;
        let mut chain = vec![0u8];
        let mut previous = rdata_start;
        for _ in 0..200 {
            let this = rdata_start + chain.len();
            chain.extend_from_slice(&pointer_to(previous));
            previous = this;
        }

        let owner = pointer_to(HEADER_LEN);
        let last_hop = pointer_to(previous);

        let bytes = response_of(
            EXAMPLE_COM,
            &[(&owner, 99, &chain), (&last_hop, 1, A_RDATA)],
        );

        assert_eq!(ResponseInfo::parse(&bytes), Err(WireError::BadName));
        assert_eq!(
            skip_name(&bytes, rdata_start + chain.len() - 2),
            Err(WireError::BadName)
        );
    }

    #[test]
    fn bad_pointers_in_soa_names_and_the_question_are_rejected() {
        let owner = pointer_to(HEADER_LEN);
        let rdata_start = owner_offset(EXAMPLE_COM) + 2 + 2 + 2 + 4 + 2;
        let soa_with_mname = |mname: [u8; 2]| {
            let mut rdata = mname.to_vec();
            rdata.extend_from_slice(&pointer_to(HEADER_LEN));
            rdata.extend_from_slice(&[0; 20]);
            let mut bytes = response_of(EXAMPLE_COM, &[(&owner, rtype::SOA, &rdata)]);
            // Move the record from the answer to the authority section.
            bytes[6..10].copy_from_slice(&[0, 0, 0, 1]);

            bytes
        };

        assert!(ResponseInfo::parse(&soa_with_mname(pointer_to(HEADER_LEN))).is_ok());
        assert_eq!(
            ResponseInfo::parse(&soa_with_mname(pointer_to(rdata_start))),
            Err(WireError::BadName)
        );
        assert_eq!(
            ResponseInfo::parse(&soa_with_mname(pointer_to(rdata_start + 8))),
            Err(WireError::BadName)
        );
        let forward_question = response_of(&pointer_to(HEADER_LEN + 2), &[]);
        assert_eq!(
            ResponseInfo::parse(&forward_question),
            Err(WireError::BadName)
        );
    }

    #[test]
    fn name_and_label_limits_are_enforced() {
        let mut long_label = vec![64];
        long_label.extend_from_slice(&[b'a'; 64]);
        long_label.push(0);
        let mut long_name = Vec::new();
        for _ in 0..5 {
            long_name.push(60);
            long_name.extend_from_slice(&[b'a'; 60]);
        }

        long_name.push(0);
        let mut longest_valid = Vec::new();
        for _ in 0..3 {
            longest_valid.push(63);
            longest_valid.extend_from_slice(&[b'a'; 63]);
        }

        longest_valid.push(61);
        longest_valid.extend_from_slice(&[b'a'; 61]);
        longest_valid.push(0);

        assert_eq!(read_name(&long_label, 0), Err(WireError::BadName));
        assert_eq!(read_name(&long_name, 0), Err(WireError::BadName));
        assert_eq!(longest_valid.len(), 255);
        assert_eq!(read_name(&longest_valid, 0).unwrap().0.as_wire().len(), 255);
        assert_eq!(read_name(&[3, b'a'], 0), Err(WireError::Truncated));
    }

    #[test]
    fn name_text_forms() {
        let name = name_of("Home.ARPA.");

        assert_eq!(name.as_wire(), b"\x04home\x04arpa\x00");
        assert_eq!(name.to_string(), "home.arpa");
        assert_eq!(Name::from_text(".").unwrap(), Name::root());
        assert_eq!(Name::root().to_string(), ".");
        assert!(Name::from_text("a..b").is_none());
        assert!(Name::from_text(&"a".repeat(64)).is_none());
        assert!(Name::from_text("ünï.example").is_none());
        assert_eq!(read_name(b"\x03a.b\x00", 0).unwrap().0.to_string(), "a\\.b");
    }

    #[test]
    fn subdomain_matching_respects_label_boundaries() {
        let domain = name_of("lan");

        assert!(name_of("lan").is_subdomain_of(&domain));
        assert!(name_of("printer.lan").is_subdomain_of(&domain));
        assert!(name_of("a.b.printer.lan.").is_subdomain_of(&domain));
        assert!(!name_of("scan").is_subdomain_of(&domain));
        assert!(!name_of("lan.example.com").is_subdomain_of(&domain));
        assert!(name_of("example.com").is_subdomain_of(&Name::root()));
    }

    fn rich_response() -> (QuerySpec, Vec<u8>, Message) {
        let query = QuerySpec::new("www.example.com.", RecordType::A);
        let response = ResponseSpec {
            answers: vec![
                cname("www.example.com.", 300, "edge.cdn.example.net."),
                a("edge.cdn.example.net.", 60, [192, 0, 2, 7].into()),
                aaaa("edge.cdn.example.net.", 120, "2001:db8::7".parse().unwrap()),
            ],
            authorities: vec![soa("example.com.", 900, 45)],
            additionals: vec![a("ns.example.com.", 3600, [192, 0, 2, 53].into())],
            edns: Some(1232),
            ..ResponseSpec::default()
        };
        let bytes = response.bytes(&query);
        let oracle = parse_with_oracle(&bytes);

        (query, bytes, oracle)
    }

    #[test]
    fn response_info_matches_the_oracle() {
        let (_, bytes, oracle) = rich_response();

        let info = ResponseInfo::parse(&bytes).unwrap();

        let oracle_ttls: Vec<u32> = oracle
            .answers
            .iter()
            .chain(&oracle.authorities)
            .chain(&oracle.additionals)
            .map(|record| record.ttl)
            .collect();
        let parsed_ttls: Vec<u32> = info
            .ttl_offsets
            .iter()
            .map(|offset| ttl_at(&bytes, *offset))
            .collect();
        assert_eq!(parsed_ttls, oracle_ttls);
        assert_eq!(info.min_ttl, Some(60));
        assert_eq!(info.negative_ttl, Some(45));
        assert_eq!(info.header.answer_count, 3);
        assert_eq!(info.header.rcode(), rcode::NOERROR);
        let opt_start = usize::from(info.opt_start.unwrap());
        assert_eq!(opt_start + 11, bytes.len());
        assert_eq!(bytes[opt_start], 0);
        assert_eq!(read_u16(&bytes, opt_start + 1).unwrap(), rtype::OPT);
    }

    #[test]
    fn negative_ttl_uses_the_smaller_of_soa_ttl_and_minimum() {
        let query = QuerySpec::new("nx.example.com.", RecordType::A);
        let small_ttl = ResponseSpec {
            authorities: vec![soa("example.com.", 30, 900)],
            rcode: rcode::NXDOMAIN,
            ..ResponseSpec::default()
        };

        let info = ResponseInfo::parse(&small_ttl.bytes(&query)).unwrap();

        assert_eq!(info.negative_ttl, Some(30));
        assert_eq!(info.min_ttl, Some(30));
        assert_eq!(info.header.rcode(), rcode::NXDOMAIN);
        assert_eq!(info.opt_start, None);
    }

    #[test]
    fn replies_are_negative_when_the_name_at_the_end_of_the_cname_chain_has_no_data() {
        let cases = [
            ("NODATA", vec![], rcode::NOERROR, true),
            ("NXDOMAIN", vec![], rcode::NXDOMAIN, true),
            (
                "NODATA behind a CNAME",
                vec![cname("www.example.com.", 300, "edge.example.net.")],
                rcode::NOERROR,
                true,
            ),
            (
                "NXDOMAIN behind two CNAMEs",
                vec![
                    cname("www.example.com.", 300, "mid.example.net."),
                    cname("mid.example.net.", 300, "edge.example.net."),
                ],
                rcode::NXDOMAIN,
                true,
            ),
            (
                "data behind a CNAME",
                vec![
                    cname("www.example.com.", 300, "edge.example.net."),
                    a("edge.example.net.", 60, [192, 0, 2, 1].into()),
                ],
                rcode::NOERROR,
                false,
            ),
            (
                "data listed before its CNAME",
                vec![
                    a("edge.example.net.", 60, [192, 0, 2, 1].into()),
                    cname("www.example.com.", 300, "edge.example.net."),
                ],
                rcode::NOERROR,
                false,
            ),
            (
                "data without a CNAME",
                vec![a("www.example.com.", 60, [192, 0, 2, 1].into())],
                rcode::NOERROR,
                false,
            ),
            ("SERVFAIL", vec![], rcode::SERVFAIL, false),
        ];

        for (label, answers, rcode, expected) in cases {
            let bytes = ResponseSpec {
                answers,
                authorities: vec![soa("example.net.", 900, 45)],
                rcode,
                ..ResponseSpec::default()
            }
            .bytes(&QuerySpec::new("www.example.com.", RecordType::A));

            let info = ResponseInfo::parse(&bytes).unwrap();

            assert_eq!(info.is_negative, expected, "{label}");
        }
    }

    #[test]
    fn a_cname_query_answered_by_a_cname_is_not_negative() {
        let bytes = ResponseSpec {
            answers: vec![cname("www.example.com.", 300, "edge.example.net.")],
            ..ResponseSpec::default()
        }
        .bytes(&QuerySpec::new("www.example.com.", RecordType::CNAME));

        assert!(!ResponseInfo::parse(&bytes).unwrap().is_negative);
    }

    #[test]
    fn a_cname_chain_longer_than_the_hop_limit_is_not_called_negative() {
        let answers = (0..20)
            .map(|hop| {
                cname(
                    &format!("h{hop}.example.com."),
                    300,
                    &format!("h{}.example.com.", hop + 1),
                )
            })
            .collect();
        let bytes = ResponseSpec {
            answers,
            authorities: vec![soa("example.com.", 900, 45)],
            ..ResponseSpec::default()
        }
        .bytes(&QuerySpec::new("h0.example.com.", RecordType::A));

        assert!(!ResponseInfo::parse(&bytes).unwrap().is_negative);
    }

    #[test]
    fn a_negative_reply_gets_its_soa_ttl_capped_by_the_minimum() {
        let query = QuerySpec::new("nx.example.com.", RecordType::A);
        let reply = |ttl, minimum, rcode| {
            ResponseSpec {
                authorities: vec![soa("example.com.", ttl, minimum)],
                rcode,
                ..ResponseSpec::default()
            }
            .bytes(&query)
        };
        let soa_ttl = |bytes: &[u8], info: &ResponseInfo| ttl_at(bytes, info.ttl_offsets[0]);

        let mut nxdomain = reply(900, 45, rcode::NXDOMAIN);
        let mut info = ResponseInfo::parse(&nxdomain).unwrap();
        info.cap_soa_ttls(&mut nxdomain);
        let mut already_lower = reply(30, 45, rcode::NXDOMAIN);
        let mut lower_info = ResponseInfo::parse(&already_lower).unwrap();
        lower_info.cap_soa_ttls(&mut already_lower);
        let mut positive = ResponseSpec {
            answers: vec![a("nx.example.com.", 300, [192, 0, 2, 1].into())],
            authorities: vec![soa("example.com.", 900, 45)],
            ..ResponseSpec::default()
        }
        .bytes(&query);
        let mut positive_info = ResponseInfo::parse(&positive).unwrap();
        positive_info.cap_soa_ttls(&mut positive);

        assert_eq!(soa_ttl(&nxdomain, &info), 45);
        assert_eq!(info.min_ttl, Some(45));
        assert_eq!(soa_ttl(&already_lower, &lower_info), 30);
        assert_eq!(ttl_at(&positive, positive_info.ttl_offsets[1]), 900);
    }

    #[test]
    fn record_data_matches_the_oracle() {
        let (_, bytes, _) = rich_response();

        let records: Vec<Record> = Records::new(&bytes)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(records.len(), 6);
        assert_eq!(
            records[0].data(&bytes).unwrap(),
            RData::Cname(Box::new(name_of("edge.cdn.example.net")))
        );
        assert_eq!(
            records[1].data(&bytes).unwrap(),
            RData::A("192.0.2.7".parse().unwrap())
        );
        assert_eq!(
            records[2].data(&bytes).unwrap(),
            RData::Aaaa("2001:db8::7".parse().unwrap())
        );
        assert_eq!(records[3].data(&bytes).unwrap(), RData::Soa { minimum: 45 });
        assert_eq!(records[3].section, Section::Authority);
        assert_eq!(records[4].section, Section::Additional);
        assert_eq!(records[0].ttl, 300);
    }

    #[test]
    fn https_hints_list_both_address_families_in_order() {
        let query = QuerySpec::new("example.com.", RecordType::HTTPS);
        let response = ResponseSpec {
            answers: vec![https(
                "example.com.",
                60,
                &["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
                &["2001:db8::1".parse().unwrap()],
            )],
            ..ResponseSpec::default()
        };
        let bytes = response.bytes(&query);

        let record = Records::new(&bytes).unwrap().next().unwrap().unwrap();
        let RData::Https(hints) = record.data(&bytes).unwrap() else {
            panic!("expected HTTPS data");
        };

        let addresses: Vec<IpAddr> = hints.collect();
        assert_eq!(
            addresses,
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn https_record_without_hints_yields_nothing() {
        let query = QuerySpec::new("example.com.", RecordType::HTTPS);
        let response = ResponseSpec {
            answers: vec![https("example.com.", 60, &[], &[])],
            ..ResponseSpec::default()
        };
        let bytes = response.bytes(&query);

        let record = Records::new(&bytes).unwrap().next().unwrap().unwrap();
        let RData::Https(mut hints) = record.data(&bytes).unwrap() else {
            panic!("expected HTTPS data");
        };

        assert_eq!(hints.next(), None);
    }

    #[test]
    fn truncated_hint_parameters_stop_quietly() {
        let mut hints = AddressHints {
            params: &[0, 4, 0, 4, 192, 0, 2, 1, 0, 6, 0, 16, 1, 2],
            current: &[],
            current_is_ipv6: false,
        };

        assert_eq!(hints.next(), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(hints.next(), None);
    }

    #[test]
    fn every_strict_prefix_of_a_response_is_an_error() {
        let (_, bytes, _) = rich_response();

        for length in 0..bytes.len() {
            assert!(
                ResponseInfo::parse(&bytes[..length]).is_err(),
                "prefix of {length} bytes parsed"
            );
        }

        assert!(ResponseInfo::parse(&bytes).is_ok());
    }

    #[test]
    fn opt_must_be_unique_in_the_additional_section_with_the_root_as_owner() {
        let (_, bytes, _) = rich_response();
        let opt = bytes[bytes.len() - 11..].to_vec();
        let mut two_opts = bytes.clone();
        two_opts.extend_from_slice(&opt);
        two_opts[11] += 1;
        let mut named_opt = bytes.clone();
        let opt_start = bytes.len() - 11;
        named_opt.splice(opt_start..opt_start + 1, [1, b'x', 0]);
        let opt_in_answers = response_of(EXAMPLE_COM, &[(&[0], rtype::OPT, &[])]);

        assert_eq!(ResponseInfo::parse(&two_opts), Err(WireError::Malformed));
        assert_eq!(ResponseInfo::parse(&named_opt), Err(WireError::Malformed));
        assert_eq!(
            ResponseInfo::parse(&opt_in_answers),
            Err(WireError::Malformed)
        );
    }

    #[test]
    fn opt_may_come_before_other_additional_records() {
        let bytes = response_with_opt_before_other_additionals();
        let oracle = parse_with_oracle(&bytes);
        assert!(oracle.edns.is_some(), "the fixture is a valid message");
        assert_eq!(oracle.additionals.len(), 3);

        let info = ResponseInfo::parse(&bytes).unwrap();

        assert_eq!(
            info.opt_start,
            Some(OPT_BEFORE_ADDITIONALS_OPT_START as u16)
        );
        let ttls: Vec<u32> = info
            .ttl_offsets
            .iter()
            .map(|offset| ttl_at(&bytes, *offset))
            .collect();
        assert_eq!(ttls, [300, 600, 900, 900]);
        assert_eq!(info.min_ttl, Some(300));
    }

    #[test]
    fn removing_the_opt_record_moves_later_records_and_their_pointers() {
        let mut bytes = response_with_opt_before_other_additionals();
        let before = bytes.len();

        remove_opt(&mut bytes, OPT_BEFORE_ADDITIONALS_OPT_START).unwrap();

        assert_eq!(bytes.len(), before - 11);
        let oracle = parse_with_oracle(&bytes);
        assert!(oracle.edns.is_none());
        let owners: Vec<String> = oracle
            .additionals
            .iter()
            .map(|record| record.name.to_ascii())
            .collect();
        assert_eq!(owners, ["ns.example.com."; 3]);
        let OracleRData::CNAME(target) = &oracle.additionals[2].data else {
            panic!("expected a CNAME");
        };

        assert_eq!(target.0.to_ascii(), "alt.ns.example.com.");
        let info = ResponseInfo::parse(&bytes).unwrap();
        assert_eq!(info.opt_start, None);
        assert_eq!(info.header.additional_count, 3);
        assert_eq!(oracle.answers.len(), 1);
    }

    #[test]
    fn removing_a_trailing_opt_record_just_cuts_it_off() {
        let (_, mut bytes, _) = rich_response();
        let opt_start = usize::from(ResponseInfo::parse(&bytes).unwrap().opt_start.unwrap());

        remove_opt(&mut bytes, opt_start).unwrap();

        assert_eq!(bytes.len(), opt_start);
        assert!(parse_with_oracle(&bytes).edns.is_none());
    }

    #[test]
    fn a_pointer_into_the_removed_opt_record_is_an_error() {
        let mut bytes = response_with_opt_before_other_additionals();
        // The second record after the OPT names its owner by the OPT's offset.
        let second_start = OPT_BEFORE_ADDITIONALS_FIRST_START + 19;
        bytes[second_start] = 0xC0;
        bytes[second_start + 1] = OPT_BEFORE_ADDITIONALS_OPT_START as u8;

        assert_eq!(
            remove_opt(&mut bytes, OPT_BEFORE_ADDITIONALS_OPT_START),
            Err(WireError::BadName)
        );
    }

    #[test]
    fn wrong_length_address_data_is_malformed() {
        let (_, bytes, _) = rich_response();
        let records: Vec<Record> = Records::new(&bytes)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut short_a = records[1].clone();
        short_a.rdata.end -= 1;
        let mut long_aaaa = records[2].clone();
        long_aaaa.rdata.end += 1;

        assert_eq!(short_a.data(&bytes), Err(WireError::Malformed));
        assert_eq!(long_aaaa.data(&bytes), Err(WireError::Malformed));
    }

    proptest! {
        #[test]
        fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = Query::parse(&bytes);
            let _ = ResponseInfo::parse(&bytes);
            let _ = read_name(&bytes, 0);
            let _ = skip_name(&bytes, 0);
            if let Ok(records) = Records::new(&bytes) {
                for record in records.flatten() {
                    if let Ok(RData::Https(hints)) = record.data(&bytes) {
                        let _ = hints.count();
                    }
                }
            }
        }

        #[test]
        fn mutated_valid_responses_never_panic(
            position in 0usize..200,
            value in any::<u8>(),
            cut in 0usize..200,
        ) {
            let (_, mut bytes, _) = rich_response();
            let position = position % bytes.len();
            bytes[position] = value;
            bytes.truncate(bytes.len() - cut % bytes.len().min(40));

            let _ = Query::parse(&bytes);
            if let Ok(records) = Records::new(&bytes) {
                for record in records.flatten() {
                    let _ = record.data(&bytes);
                }
            }

            let _ = ResponseInfo::parse(&bytes);
        }

        #[test]
        fn removing_the_opt_record_of_a_mutated_response_never_panics(
            position in 0usize..200,
            value in any::<u8>(),
        ) {
            let mut bytes = response_with_opt_before_other_additionals();
            let position = position % bytes.len();
            bytes[position] = value;

            if let Ok(ResponseInfo { opt_start: Some(opt_start), .. }) = ResponseInfo::parse(&bytes) {
                let _ = remove_opt(&mut bytes, usize::from(opt_start));
            }
        }

        #[test]
        fn generated_responses_match_the_oracle(
            ttls in proptest::collection::vec(0u32..100_000, 1..8),
            labels in proptest::collection::vec("[a-z0-9]{1,12}", 1..4),
        ) {
            let owner = format!("{}.", labels.join("."));
            let answers: Vec<_> = ttls
                .iter()
                .enumerate()
                .map(|(index, ttl)| a(&owner, *ttl, [10, 0, 0, index as u8].into()))
                .collect();
            let response = ResponseSpec { answers, edns: Some(1232), ..ResponseSpec::default() };
            let bytes = response.bytes(&QuerySpec::new(&owner, RecordType::A));

            let info = ResponseInfo::parse(&bytes).unwrap();

            let parsed: Vec<u32> = info.ttl_offsets.iter().map(|offset| ttl_at(&bytes, *offset)).collect();
            prop_assert_eq!(parsed, ttls.clone());
            prop_assert_eq!(info.min_ttl, ttls.iter().copied().min());
        }
    }
}
