//! Where an encrypted upstream lives: the `https://` and `tls://` URL forms,
//! and how a host name in them is turned into addresses (bootstrap).

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::Uri;
use http::uri::Authority;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use super::{UpstreamError, udp};
use crate::dns::wire::{CLASS_IN, Name, RData, Records, Section, flags, rtype};

const DEFAULT_DOH_PORT: u16 = 443;
const DEFAULT_DOT_PORT: u16 = 853;
const DEFAULT_DOH_PATH: &str = "/dns-query";
const BOOTSTRAP_PORT: u16 = 53;
const BOOTSTRAP_ATTEMPT: Duration = Duration::from_secs(1);
/// Answers to a plain query without EDNS fit in 512 bytes.
const BOOTSTRAP_REPLY_MAX: usize = 512;

/// Resolves upstream host names through plain DNS servers whose addresses are
/// configured, since the system resolver is this very program.
pub struct Bootstrap {
    servers: Vec<SocketAddr>,
}

impl Bootstrap {
    pub fn new(addresses: &[IpAddr]) -> Bootstrap {
        Bootstrap::at(
            addresses
                .iter()
                .map(|ip| SocketAddr::new(*ip, BOOTSTRAP_PORT))
                .collect(),
        )
    }

    /// Servers on explicit ports, for tests.
    pub fn at(servers: Vec<SocketAddr>) -> Bootstrap {
        Bootstrap { servers }
    }

    fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// IPv4 addresses first, then IPv6, from the first server that knows any.
    pub async fn resolve(
        &self,
        host: &str,
        deadline: Instant,
    ) -> Result<Vec<IpAddr>, UpstreamError> {
        let Some(name) = Name::from_text(host) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid host name").into());
        };

        for server in &self.servers {
            let attempt_deadline = deadline.min(Instant::now() + BOOTSTRAP_ATTEMPT);
            let (v4, v6) = tokio::join!(
                lookup(*server, &name, rtype::A, attempt_deadline),
                lookup(*server, &name, rtype::AAAA, attempt_deadline),
            );
            let mut addresses = v4;
            addresses.extend(v6);

            if !addresses.is_empty() {
                return Ok(addresses);
            }
        }

        Err(io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}")).into())
    }
}

/// The addresses in the answer section, or none if the server does not answer.
async fn lookup(
    server: SocketAddr,
    name: &Name,
    record_type: u16,
    deadline: Instant,
) -> Vec<IpAddr> {
    let mut query = vec![0, 0];
    query.extend_from_slice(&flags::RD.to_be_bytes());
    query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(name.as_wire());
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());

    let Ok(reply) = udp::exchange(server, &mut query, BOOTSTRAP_REPLY_MAX, deadline).await else {
        return Vec::new();
    };
    let Ok(records) = Records::new(&reply) else {
        return Vec::new();
    };

    records
        .map_while(Result::ok)
        .filter(|record| record.section == Section::Answer)
        .filter_map(|record| match record.data(&reply) {
            Ok(RData::A(address)) => Some(IpAddr::V4(address)),
            Ok(RData::Aaaa(address)) => Some(IpAddr::V6(address)),
            _ => None,
        })
        .collect()
}

enum Host {
    Ip(IpAddr),
    Name(String),
}

/// The TCP endpoint of an upstream: an IP, or a host name that is resolved
/// when needed and again after a connection attempt fails.
pub struct Remote {
    host: Host,
    port: u16,
    bootstrap: Arc<Bootstrap>,
    resolved: Mutex<Vec<IpAddr>>,
}

impl Remote {
    pub fn at(address: SocketAddr) -> Remote {
        Remote {
            host: Host::Ip(address.ip()),
            port: address.port(),
            bootstrap: Arc::new(Bootstrap::at(Vec::new())),
            resolved: Mutex::new(Vec::new()),
        }
    }

    /// Connects to the addresses in turn, runs `attempt` on the first
    /// connection that opens, and returns its result. An attempt that fails
    /// or runs out of time moves on to the next address, so `attempt` should
    /// include everything that can make an address unusable (the TLS
    /// handshake). Each address but the last gets half of the time left. When
    /// every address fails, the resolved addresses are forgotten and the next
    /// call resolves the name again.
    pub async fn connect_with<T, F, Fut>(
        &self,
        deadline: Instant,
        mut attempt: F,
    ) -> Result<T, UpstreamError>
    where
        F: FnMut(TcpStream) -> Fut,
        Fut: Future<Output = Result<T, UpstreamError>>,
    {
        let addresses = self.addresses(deadline).await?;
        let mut last_error = UpstreamError::Timeout;

        for (index, ip) in addresses.iter().enumerate() {
            let attempt_deadline = if index + 1 == addresses.len() {
                deadline
            } else {
                let now = Instant::now();

                now + deadline.saturating_duration_since(now) / 2
            };
            let connecting = async {
                let stream = TcpStream::connect((*ip, self.port)).await?;
                stream.set_nodelay(true)?;

                attempt(stream).await
            };

            match timeout_at(attempt_deadline, connecting).await {
                Ok(Ok(connected)) => {
                    self.prefer(*ip);

                    return Ok(connected);
                }

                Ok(Err(error)) => {
                    last_error = error;
                }

                Err(_) => {
                    last_error = UpstreamError::Timeout;
                }
            }
        }

        self.resolved.lock().unwrap().clear();

        Err(last_error)
    }

    /// Makes `ip` the first address to try next time.
    fn prefer(&self, ip: IpAddr) {
        let mut resolved = self.resolved.lock().unwrap();
        if let Some(position) = resolved.iter().position(|address| *address == ip) {
            resolved.swap(0, position);
        }
    }

    async fn addresses(&self, deadline: Instant) -> Result<Vec<IpAddr>, UpstreamError> {
        let name = match &self.host {
            Host::Ip(ip) => return Ok(vec![*ip]),
            Host::Name(name) => name,
        };

        let cached = self.resolved.lock().unwrap().clone();
        if !cached.is_empty() {
            return Ok(cached);
        }

        let addresses = self.bootstrap.resolve(name, deadline).await?;
        *self.resolved.lock().unwrap() = addresses.clone();

        Ok(addresses)
    }
}

/// A parsed `https://` or `tls://` upstream.
pub struct Target {
    pub remote: Remote,
    /// The name TLS checks the certificate against and sends as SNI.
    pub server_name: ServerName<'static>,
}

/// `https://host-or-ip[:port][/path]`. Returns the full request URI as well.
pub fn parse_https(
    spec: &str,
    rest: &str,
    bootstrap: &Arc<Bootstrap>,
) -> Result<(Target, Uri), String> {
    let (authority_text, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, ""),
    };
    let path = if path.is_empty() || path == "/" {
        DEFAULT_DOH_PATH
    } else {
        path
    };

    let (host, port) = parse_authority(spec, authority_text, DEFAULT_DOH_PORT)?;
    let uri = format!("https://{authority_text}{path}")
        .parse::<Uri>()
        .map_err(|_| format!("upstream {spec}: invalid URL"))?;
    let server_name = server_name_for(spec, &host_text(&host))?;

    Ok((
        Target {
            remote: remote_for(spec, host, port, bootstrap)?,
            server_name,
        },
        uri,
    ))
}

/// `tls://host-or-ip[:port][#servername]`. Without a server name the host
/// itself is checked against the certificate.
pub fn parse_tls(spec: &str, rest: &str, bootstrap: &Arc<Bootstrap>) -> Result<Target, String> {
    let (authority_text, name) = rest.split_once('#').unwrap_or((rest, ""));
    let (host, port) = parse_authority(spec, authority_text, DEFAULT_DOT_PORT)?;
    let name = if name.is_empty() {
        host_text(&host)
    } else {
        name.to_string()
    };

    Ok(Target {
        server_name: server_name_for(spec, &name)?,
        remote: remote_for(spec, host, port, bootstrap)?,
    })
}

fn host_text(host: &Host) -> String {
    match host {
        Host::Ip(ip) => ip.to_string(),
        Host::Name(name) => name.clone(),
    }
}

fn parse_authority(spec: &str, text: &str, default_port: u16) -> Result<(Host, u16), String> {
    if text.contains('@') {
        return Err(format!("upstream {spec}: user names are not supported"));
    }

    let authority = Authority::from_str(text).map_err(|_| {
        format!("upstream {spec}: expected a host name or IP address and optional port")
    })?;
    let bracketed_host = authority.host();
    let host = bracketed_host.trim_matches(['[', ']']);
    let port = match text[bracketed_host.len()..].strip_prefix(':') {
        None => default_port,
        Some(digits) => digits
            .parse()
            .map_err(|_| format!("upstream {spec}: invalid port"))?,
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((Host::Ip(ip), port));
    }

    let allowed = |character: char| character.is_ascii_alphanumeric() || "-_.".contains(character);
    if !host.chars().all(allowed) || Name::from_text(host).is_none() {
        return Err(format!("upstream {spec}: invalid host name"));
    }

    Ok((Host::Name(host.to_string()), port))
}

fn server_name_for(spec: &str, name: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(name.to_string())
        .map_err(|_| format!("upstream {spec}: invalid server name"))
}

fn remote_for(
    spec: &str,
    host: Host,
    port: u16,
    bootstrap: &Arc<Bootstrap>,
) -> Result<Remote, String> {
    if matches!(host, Host::Name(_)) && bootstrap.is_empty() {
        return Err(format!(
            "upstream {spec}: a host name needs upstream.bootstrap (plain DNS server IPs to resolve it)"
        ));
    }

    Ok(Remote {
        host,
        port,
        bootstrap: Arc::clone(bootstrap),
        resolved: Mutex::new(Vec::new()),
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;

    use tokio::net::TcpListener;

    use super::*;
    use crate::upstream::test_dns::{FakeDns, fake_dns};

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(3)
    }

    async fn accept(stream: TcpStream) -> Result<TcpStream, UpstreamError> {
        Ok(stream)
    }

    fn bootstrap_at(servers: &[&FakeDns]) -> Arc<Bootstrap> {
        Arc::new(Bootstrap::at(
            servers.iter().map(|server| server.address).collect(),
        ))
    }

    fn some_bootstrap() -> Arc<Bootstrap> {
        Arc::new(Bootstrap::new(&["9.9.9.9".parse().unwrap()]))
    }

    fn no_bootstrap() -> Arc<Bootstrap> {
        Arc::new(Bootstrap::new(&[]))
    }

    fn host_of(remote: &Remote) -> (String, u16) {
        (host_text(&remote.host), remote.port)
    }

    #[test]
    fn https_urls_with_an_ip_use_the_ip_for_connecting_and_for_the_certificate() {
        let (target, uri) = parse_https("u", "1.1.1.1/dns-query", &no_bootstrap()).unwrap();

        assert_eq!(host_of(&target.remote), ("1.1.1.1".to_string(), 443));
        assert_eq!(target.server_name, ServerName::try_from("1.1.1.1").unwrap());
        assert!(matches!(target.server_name, ServerName::IpAddress(_)));
        assert_eq!(uri, "https://1.1.1.1/dns-query");
    }

    #[test]
    fn https_urls_take_a_port_a_query_string_and_an_ipv6_host() {
        let (target, uri) = parse_https(
            "u",
            "[2606:4700:4700::1111]:8443/dns-query?x=1",
            &no_bootstrap(),
        )
        .unwrap();

        assert_eq!(
            host_of(&target.remote),
            ("2606:4700:4700::1111".to_string(), 8443)
        );
        assert_eq!(uri, "https://[2606:4700:4700::1111]:8443/dns-query?x=1");
    }

    #[test]
    fn https_urls_without_a_path_use_the_standard_one() {
        let (_, bare) = parse_https("u", "9.9.9.10", &no_bootstrap()).unwrap();
        let (_, slash) = parse_https("u", "9.9.9.10/", &no_bootstrap()).unwrap();

        assert_eq!(bare, "https://9.9.9.10/dns-query");
        assert_eq!(slash, "https://9.9.9.10/dns-query");
    }

    #[test]
    fn https_urls_with_a_host_name_need_a_bootstrap_and_check_the_name() {
        let (target, uri) = parse_https("u", "dns.example/dns-query", &some_bootstrap()).unwrap();

        assert_eq!(host_of(&target.remote), ("dns.example".to_string(), 443));
        assert_eq!(
            target.server_name,
            ServerName::try_from("dns.example").unwrap()
        );
        assert_eq!(uri, "https://dns.example/dns-query");
        let error = parse_https("SPEC", "dns.example/dns-query", &no_bootstrap())
            .err()
            .unwrap();
        assert!(error.contains("upstream.bootstrap"), "{error}");
    }

    #[test]
    fn tls_urls_use_the_fragment_as_the_server_name() {
        let named = parse_tls("u", "1.1.1.1#cloudflare-dns.com", &no_bootstrap()).unwrap();
        let ip_only = parse_tls("u", "9.9.9.10", &no_bootstrap()).unwrap();
        let with_port = parse_tls("u", "1.1.1.1:8853#cloudflare-dns.com", &no_bootstrap()).unwrap();
        let named_host = parse_tls("u", "dns.quad9.net", &some_bootstrap()).unwrap();
        let renamed_host = parse_tls("u", "dns.example#real.example", &some_bootstrap()).unwrap();

        assert_eq!(host_of(&named.remote), ("1.1.1.1".to_string(), 853));
        assert_eq!(
            named.server_name,
            ServerName::try_from("cloudflare-dns.com").unwrap()
        );
        assert_eq!(host_of(&ip_only.remote), ("9.9.9.10".to_string(), 853));
        assert!(matches!(ip_only.server_name, ServerName::IpAddress(_)));
        assert_eq!(host_of(&with_port.remote), ("1.1.1.1".to_string(), 8853));
        assert_eq!(
            host_of(&named_host.remote),
            ("dns.quad9.net".to_string(), 853)
        );
        assert_eq!(
            named_host.server_name,
            ServerName::try_from("dns.quad9.net").unwrap()
        );
        assert_eq!(
            host_of(&renamed_host.remote),
            ("dns.example".to_string(), 853)
        );
        assert_eq!(
            renamed_host.server_name,
            ServerName::try_from("real.example").unwrap()
        );
    }

    #[test]
    fn malformed_urls_are_rejected_with_the_url_in_the_message() {
        for rest in ["user@1.1.1.1", "1.1.1.1:notaport", "", "bad name"] {
            let https = parse_https("SPEC", rest, &some_bootstrap()).err().unwrap();
            let tls = parse_tls("SPEC", rest, &some_bootstrap()).err().unwrap();

            assert!(https.contains("SPEC"), "{rest}: {https}");
            assert!(tls.contains("SPEC"), "{rest}: {tls}");
        }
        let name = parse_tls("SPEC", "1.1.1.1#bad name", &some_bootstrap())
            .err()
            .unwrap();
        assert!(name.contains("server name"), "{name}");
    }

    #[tokio::test]
    async fn the_bootstrap_returns_ipv4_then_ipv6_addresses() {
        let dns = fake_dns(
            vec!["192.0.2.7".parse().unwrap()],
            vec!["2001:db8::7".parse().unwrap()],
        )
        .await;

        let addresses = bootstrap_at(&[&dns])
            .resolve("dns.example", later())
            .await
            .unwrap();

        assert_eq!(
            addresses,
            vec![
                "192.0.2.7".parse::<IpAddr>().unwrap(),
                "2001:db8::7".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn the_bootstrap_asks_the_next_server_when_one_knows_nothing() {
        let empty = fake_dns(Vec::new(), Vec::new()).await;
        let knows = fake_dns(vec!["192.0.2.8".parse().unwrap()], Vec::new()).await;

        let addresses = bootstrap_at(&[&empty, &knows])
            .resolve("dns.example", later())
            .await
            .unwrap();

        assert_eq!(addresses, vec!["192.0.2.8".parse::<IpAddr>().unwrap()]);
        assert_eq!(empty.queries.load(Ordering::SeqCst), 2, "A and AAAA");
    }

    #[tokio::test]
    async fn a_name_nobody_knows_is_an_error() {
        let empty = fake_dns(Vec::new(), Vec::new()).await;

        let result = bootstrap_at(&[&empty])
            .resolve("dns.example", later())
            .await;

        assert!(matches!(result, Err(UpstreamError::Io(_))));
    }

    #[tokio::test]
    async fn a_remote_resolves_once_and_connects_to_the_resolved_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dns = fake_dns(vec![Ipv4Addr::LOCALHOST], Vec::new()).await;
        let target =
            parse_tls("u", &format!("dns.example:{port}"), &bootstrap_at(&[&dns])).unwrap();

        target.remote.connect_with(later(), accept).await.unwrap();
        target.remote.connect_with(later(), accept).await.unwrap();

        assert_eq!(dns.queries.load(Ordering::SeqCst), 2, "one A and one AAAA");
    }

    #[tokio::test]
    async fn a_failed_connection_makes_the_remote_resolve_again() {
        let free_port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let dns = fake_dns(vec![Ipv4Addr::LOCALHOST], Vec::new()).await;
        let target = parse_tls(
            "u",
            &format!("dns.example:{free_port}"),
            &bootstrap_at(&[&dns]),
        )
        .unwrap();

        let refused = target.remote.connect_with(later(), accept).await;
        assert!(matches!(refused, Err(UpstreamError::Io(_))));
        let listener = TcpListener::bind(("127.0.0.1", free_port)).await.unwrap();
        let connected = target.remote.connect_with(later(), accept).await;

        assert!(connected.is_ok());
        assert_eq!(dns.queries.load(Ordering::SeqCst), 4, "resolved twice");
        drop(listener);
    }

    #[tokio::test]
    async fn an_ip_remote_never_asks_the_bootstrap() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Remote::at(listener.local_addr().unwrap());

        assert!(remote.connect_with(later(), accept).await.is_ok());
    }
}
