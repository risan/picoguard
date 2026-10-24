//! DNS messages for the upstream tests.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hickory_proto::rr::RecordType;
use tokio::net::UdpSocket;

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

/// A plain DNS server that knows `v4` and `v6` addresses for every name
/// and counts the queries it receives.
pub struct FakeDns {
    pub address: SocketAddr,
    pub queries: Arc<AtomicUsize>,
    v4: Arc<Mutex<Vec<Ipv4Addr>>>,
}

impl FakeDns {
    /// From now on the server answers A queries with `addresses`.
    pub fn set_v4(&self, addresses: Vec<Ipv4Addr>) {
        *self.v4.lock().unwrap() = addresses;
    }
}

pub async fn fake_dns(v4: Vec<Ipv4Addr>, v6: Vec<Ipv6Addr>) -> FakeDns {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&queries);
    let v4 = Arc::new(Mutex::new(v4));
    let served_v4 = Arc::clone(&v4);

    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            counter.fetch_add(1, Ordering::SeqCst);
            let query = &buffer[..length];
            let question_end = wire::skip_name(query, wire::HEADER_LEN).unwrap() + 4;
            let asked = u16::from_be_bytes([query[question_end - 4], query[question_end - 3]]);
            let rdata: Vec<Vec<u8>> = if asked == rtype::A {
                served_v4
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|ip| ip.octets().to_vec())
                    .collect()
            } else {
                v6.iter().map(|ip| ip.octets().to_vec()).collect()
            };

            let mut reply = query[..question_end].to_vec();
            reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            reply[6..8].copy_from_slice(&(rdata.len() as u16).to_be_bytes());
            reply[10..12].copy_from_slice(&[0, 0]);
            for data in rdata {
                reply.extend_from_slice(&[0xC0, 0x0C]);
                reply.extend_from_slice(&asked.to_be_bytes());
                reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                reply.extend_from_slice(&(data.len() as u16).to_be_bytes());
                reply.extend_from_slice(&data);
            }

            let _ = socket.send_to(&reply, peer).await;
        }
    });

    FakeDns {
        address,
        queries,
        v4,
    }
}
