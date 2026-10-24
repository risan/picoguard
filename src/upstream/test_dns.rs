//! DNS messages for the upstream tests.

use hickory_proto::rr::RecordType;

use crate::dns::test_util::QuerySpec;
use crate::dns::wire::{self, flags, rtype};

pub const ANSWER_MARKER: [u8; 4] = [192, 0, 2, 1];

pub fn query_for(name: &str) -> Vec<u8> {
    QuerySpec::new(name, RecordType::A).bytes()
}

/// A reply to `request` with one A record, optionally with TC set.
pub fn answer(request: &[u8], address: [u8; 4], truncated: bool) -> Vec<u8> {
    let question_end = wire::skip_name(request, wire::HEADER_LEN).unwrap() + 4;
    let mut reply = request[..question_end].to_vec();
    let reply_flags = 0x8180u16 | if truncated { flags::TC } else { 0 };
    reply[2..4].copy_from_slice(&reply_flags.to_be_bytes());
    reply[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
    reply.extend_from_slice(&[0xC0, 0x0C]);
    reply.extend_from_slice(&rtype::A.to_be_bytes());
    reply.extend_from_slice(&[0, 1, 0, 0, 0, 60, 0, 4]);
    reply.extend_from_slice(&address);

    reply
}

pub fn address_of(reply: &[u8]) -> [u8; 4] {
    reply[reply.len() - 4..].try_into().unwrap()
}
