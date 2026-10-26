//! `picoguard dns-check ADDRESS PORT`: one A query for example.com, so the installer can ask
//! a running picoguard whether it answers without `dig` or `nslookup`.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::dns::wire::{self, CLASS_IN, Header, Name, flags, rcode, rtype};
use crate::upstream::random_u64;

/// How long the command waits for a reply.
pub const WAIT: Duration = Duration::from_secs(2);

const QUESTION_NAME: &str = "example.com";
const RECEIVE_BUFFER_LEN: usize = 4096;

#[derive(Debug, PartialEq)]
enum Reply {
    /// Not an answer to the query: another id, not a response, or not a DNS message.
    Ignore,
    Accept,
    Refuse(String),
}

/// Asks `target` for `example.com` and waits at most `wait`. Ok for a reply that answers the
/// query with `NOERROR` or `NXDOMAIN`.
pub fn ask(target: SocketAddr, wait: Duration) -> Result<(), String> {
    let deadline = Instant::now() + wait;
    let local: SocketAddr = if target.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let cannot = |error: io::Error| format!("cannot ask {target}: {error}");
    let socket = UdpSocket::bind(local).map_err(cannot)?;
    socket.connect(target).map_err(cannot)?;

    let query = build_query(random_u64() as u16);
    socket.send(&query).map_err(cannot)?;

    let mut buffer = [0u8; RECEIVE_BUFFER_LEN];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "no answer from {target} within {} s",
                wait.as_secs()
            ));
        }

        socket.set_read_timeout(Some(remaining)).map_err(cannot)?;

        match socket.recv(&mut buffer) {
            Ok(length) => match judge(&query, &buffer[..length]) {
                Reply::Ignore => {}

                Reply::Accept => {
                    return Ok(());
                }

                Reply::Refuse(reason) => {
                    return Err(format!("{reason} from {target}"));
                }
            },

            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}

            Err(error) => {
                return Err(cannot(error));
            }
        }
    }
}

fn build_query(id: u16) -> Vec<u8> {
    let name = Name::from_text(QUESTION_NAME).expect("the question name is valid");
    let mut query = Vec::with_capacity(wire::HEADER_LEN + name.as_wire().len() + 4);

    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&flags::RD.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[0; 6]);
    query.extend_from_slice(name.as_wire());
    query.extend_from_slice(&rtype::A.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());

    query
}

fn judge(query: &[u8], reply: &[u8]) -> Reply {
    let (Ok(asked), Ok(answered)) = (Header::parse(query), Header::parse(reply)) else {
        return Reply::Ignore;
    };

    if !answered.is_response() || answered.id != asked.id {
        return Reply::Ignore;
    }

    let question = &query[wire::HEADER_LEN..];
    let echoed = reply.get(wire::HEADER_LEN..wire::HEADER_LEN + question.len());

    if answered.question_count != 1
        || !echoed.is_some_and(|echoed| echoed.eq_ignore_ascii_case(question))
    {
        return Reply::Refuse("an answer to another question".to_string());
    }

    match answered.rcode() {
        rcode::NOERROR | rcode::NXDOMAIN => Reply::Accept,

        rcode::FORMERR => Reply::Refuse("FORMERR".to_string()),
        rcode::SERVFAIL => Reply::Refuse("SERVFAIL".to_string()),
        rcode::NOTIMP => Reply::Refuse("NOTIMP".to_string()),
        rcode::REFUSED => Reply::Refuse("REFUSED".to_string()),
        other => Reply::Refuse(format!("response code {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u16 = 0xBEEF;

    fn reply_with(query: &[u8], code: u8) -> Vec<u8> {
        let mut reply = query.to_vec();
        reply[2] |= 0x80;
        reply[3] = (reply[3] & 0xF0) | code;

        reply
    }

    #[test]
    fn the_query_asks_for_example_com_a_in() {
        let query = build_query(ID);
        let header = Header::parse(&query).unwrap();

        assert_eq!(header.id, ID);
        assert!(!header.is_response());
        assert!(header.recursion_desired());
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 0);
        assert_eq!(
            &query[wire::HEADER_LEN..],
            b"\x07example\x03com\x00\x00\x01\x00\x01"
        );
    }

    #[test]
    fn replies_are_judged_by_id_question_and_rcode() {
        let query = build_query(ID);

        for code in [rcode::NOERROR, rcode::NXDOMAIN] {
            assert_eq!(judge(&query, &reply_with(&query, code)), Reply::Accept);
        }

        for (code, name) in [(rcode::SERVFAIL, "SERVFAIL"), (rcode::REFUSED, "REFUSED")] {
            assert_eq!(
                judge(&query, &reply_with(&query, code)),
                Reply::Refuse(name.to_string())
            );
        }

        let mut other_question = reply_with(&query, rcode::NOERROR);
        let at = other_question.len() - 7;
        other_question[at..at + 3].copy_from_slice(b"org");
        assert!(matches!(judge(&query, &other_question), Reply::Refuse(_)));

        let mut upper_case = reply_with(&query, rcode::NOERROR);
        upper_case[wire::HEADER_LEN + 1..wire::HEADER_LEN + 8].copy_from_slice(b"EXAMPLE");
        assert_eq!(judge(&query, &upper_case), Reply::Accept);

        let mut no_question = reply_with(&query, rcode::NOERROR);
        no_question[5] = 0;
        assert!(matches!(judge(&query, &no_question), Reply::Refuse(_)));

        let mut another_id = reply_with(&query, rcode::NOERROR);
        another_id[0] ^= 0xFF;
        assert_eq!(judge(&query, &another_id), Reply::Ignore);

        assert_eq!(judge(&query, &query), Reply::Ignore);
        assert_eq!(
            judge(&query, &reply_with(&query, rcode::NOERROR)[..6]),
            Reply::Ignore
        );
    }
}
