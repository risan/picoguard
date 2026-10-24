//! TLS client settings for DoH and DoT (D10): rustls with the `ring`
//! provider and the webpki root store. A CPU without AES offers only
//! ChaCha20-Poly1305 suites, which are about three times faster there in
//! software, and falls back to the full list for an upstream that has none.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::{self, cipher_suite};
use rustls::pki_types::ServerName;
use rustls::{AlertDescription, ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::UpstreamError;
use super::endpoint::Remote;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alpn {
    H2,
    Dot,
}

impl Alpn {
    fn protocol(self) -> &'static [u8] {
        match self {
            Alpn::H2 => b"h2",
            Alpn::Dot => b"dot",
        }
    }
}

/// True when the CPU has AES instructions. A platform without a detection
/// method counts as having them, so it offers the default suite list.
pub fn cpu_has_aes() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        std::arch::is_x86_feature_detected!("aes")
    }

    // The standard library cannot detect features on 32-bit ARM.
    #[cfg(target_arch = "arm")]
    {
        std::fs::read_to_string("/proc/cpuinfo").is_ok_and(|cpuinfo| cpuinfo_lists_aes(&cpuinfo))
    }

    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "arm"
    )))]
    {
        true
    }
}

/// True when a `Features` (ARM) or `flags` (x86) line of /proc/cpuinfo lists `aes`.
#[cfg(any(target_arch = "arm", test))]
fn cpuinfo_lists_aes(cpuinfo: &str) -> bool {
    cpuinfo
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| matches!(key.trim(), "Features" | "flags"))
        .any(|(_, value)| value.split_whitespace().any(|feature| feature == "aes"))
}

/// The client configurations, one per ALPN protocol and suite list, built on
/// first use.
pub struct Tls {
    roots: Arc<RootCertStore>,
    has_aes: bool,
    configs: [OnceLock<Arc<ClientConfig>>; 4],
}

impl Tls {
    pub fn with_webpki_roots() -> Tls {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        Tls::with_roots(Arc::new(roots), cpu_has_aes())
    }

    /// `has_aes` is a parameter so tests can run either policy on any CPU.
    pub fn with_roots(roots: Arc<RootCertStore>, has_aes: bool) -> Tls {
        Tls {
            roots,
            has_aes,
            configs: Default::default(),
        }
    }

    /// The configuration for `alpn`. Without AES, `full_suites` false means
    /// ChaCha20-Poly1305 only.
    fn config(&self, alpn: Alpn, full_suites: bool) -> Arc<ClientConfig> {
        let chacha_only = !self.has_aes && !full_suites;
        let slot = usize::from(alpn == Alpn::Dot) * 2 + usize::from(chacha_only);

        Arc::clone(self.configs[slot].get_or_init(|| {
            let mut provider = ring::default_provider();
            if chacha_only {
                provider.cipher_suites = chacha_suites();
            }

            let mut config = build_config(provider, Arc::clone(&self.roots));
            config.alpn_protocols = vec![alpn.protocol().to_vec()];

            Arc::new(config)
        }))
    }
}

fn chacha_suites() -> Vec<rustls::SupportedCipherSuite> {
    vec![
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

fn build_config(provider: CryptoProvider, roots: Arc<RootCertStore>) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// True when the server refused the handshake because none of the offered
/// cipher suites was acceptable to it.
fn lacks_shared_cipher(error: &io::Error) -> bool {
    let alert = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());

    matches!(
        alert,
        Some(rustls::Error::AlertReceived(
            AlertDescription::HandshakeFailure | AlertDescription::InsufficientSecurity
        ))
    )
}

/// Opens TLS connections to one upstream and remembers whether it needs the
/// full suite list.
pub struct TlsDialer {
    tls: Arc<Tls>,
    alpn: Alpn,
    server_name: ServerName<'static>,
    remote: Remote,
    label: String,
    needs_full_suites: AtomicBool,
}

impl TlsDialer {
    pub fn new(
        tls: Arc<Tls>,
        alpn: Alpn,
        server_name: ServerName<'static>,
        remote: Remote,
        label: String,
    ) -> TlsDialer {
        TlsDialer {
            tls,
            alpn,
            server_name,
            remote,
            label,
            needs_full_suites: AtomicBool::new(false),
        }
    }

    pub async fn connect(&self, deadline: Instant) -> Result<TlsStream<TcpStream>, UpstreamError> {
        let full_suites = self.needs_full_suites.load(Ordering::Relaxed);

        match self.handshake(full_suites, deadline).await {
            Err(UpstreamError::Io(error)) if !full_suites && lacks_shared_cipher(&error) => {
                if !self.needs_full_suites.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "upstream {} has no ChaCha20-Poly1305 suite, offering all suites to it from now on",
                        self.label
                    );
                }

                self.handshake(true, deadline).await
            }

            result => result,
        }
    }

    async fn handshake(
        &self,
        full_suites: bool,
        deadline: Instant,
    ) -> Result<TlsStream<TcpStream>, UpstreamError> {
        let tcp = self.remote.connect(deadline).await?;

        let connector = TlsConnector::from(self.tls.config(self.alpn, full_suites));
        let Ok(handshake) =
            timeout_at(deadline, connector.connect(self.server_name.clone(), tcp)).await
        else {
            return Err(UpstreamError::Timeout);
        };

        Ok(handshake?)
    }

    #[cfg(test)]
    fn offers_full_suites(&self) -> bool {
        self.needs_full_suites.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustls::SupportedCipherSuite;
    use rustls::crypto::ring::cipher_suite;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::upstream::test_tls::{TestPki, TlsServer};

    const AES_256: SupportedCipherSuite = cipher_suite::TLS13_AES_256_GCM_SHA384;
    const CHACHA: SupportedCipherSuite = cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// A server that completes handshakes and then holds the connection.
    async fn idle_server(pki: &TestPki, alpn: &[&str], provider: CryptoProvider) -> TlsServer {
        let config = pki.server_config(alpn, provider);

        TlsServer::start(config, |mut stream| async move {
            let _ = stream.shutdown().await;
        })
        .await
    }

    fn dialer(pki: &TestPki, has_aes: bool, alpn: Alpn, server: &TlsServer) -> TlsDialer {
        let tls = Arc::new(Tls::with_roots(pki.roots(), has_aes));
        let name = ServerName::try_from("localhost").unwrap();

        TlsDialer::new(
            tls,
            alpn,
            name,
            Remote::at(server.address),
            "test".to_string(),
        )
    }

    async fn negotiated(dialer: &TlsDialer) -> SupportedCipherSuite {
        let stream = dialer.connect(deadline()).await.unwrap();

        stream.get_ref().1.negotiated_cipher_suite().unwrap()
    }

    fn aes_only_provider() -> CryptoProvider {
        let mut provider = ring::default_provider();
        provider.cipher_suites = vec![
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ];

        provider
    }

    #[tokio::test]
    async fn without_aes_chacha_wins_even_if_the_server_prefers_aes() {
        let pki = TestPki::new();
        let server = idle_server(&pki, &["h2"], ring::default_provider()).await;

        let suite = negotiated(&dialer(&pki, false, Alpn::H2, &server)).await;

        assert_eq!(suite.suite(), CHACHA.suite());
    }

    #[tokio::test]
    async fn with_aes_the_server_keeps_its_aes_preference() {
        let pki = TestPki::new();
        let server = idle_server(&pki, &["h2"], ring::default_provider()).await;

        let suite = negotiated(&dialer(&pki, true, Alpn::H2, &server)).await;

        assert_eq!(suite.suite(), AES_256.suite());
    }

    #[tokio::test]
    async fn without_aes_chacha_is_also_used_on_tls_1_2() {
        let pki = TestPki::new();
        let config = pki.tls12_server_config(&["h2"], ring::default_provider());
        let server = TlsServer::start(config, |mut stream| async move {
            let _ = stream.shutdown().await;
        })
        .await;

        let suite = negotiated(&dialer(&pki, false, Alpn::H2, &server)).await;

        assert_eq!(
            suite.suite(),
            cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.suite()
        );
    }

    #[tokio::test]
    async fn a_server_without_chacha_is_retried_once_with_the_full_list_and_remembered() {
        let pki = TestPki::new();
        let server = idle_server(&pki, &["h2"], aes_only_provider()).await;
        let dialer = dialer(&pki, false, Alpn::H2, &server);

        let first = negotiated(&dialer).await;

        assert_eq!(
            first.suite(),
            cipher_suite::TLS13_AES_128_GCM_SHA256.suite()
        );
        assert!(dialer.offers_full_suites());
        server.wait_for_handshakes(1).await;
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            2,
            "refused, then served"
        );
        assert_eq!(server.handshakes.load(Ordering::SeqCst), 1);

        negotiated(&dialer).await;

        server.wait_for_handshakes(2).await;
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            3,
            "no second fallback"
        );
        assert_eq!(server.handshakes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failure_unrelated_to_ciphers_does_not_trigger_the_fallback() {
        let pki = TestPki::new();
        let server = idle_server(&pki, &["h2"], ring::default_provider()).await;
        let tls = Arc::new(Tls::with_roots(pki.roots(), false));
        let wrong_name = ServerName::try_from("other.example").unwrap();
        let dialer = TlsDialer::new(
            tls,
            Alpn::H2,
            wrong_name,
            Remote::at(server.address),
            "test".into(),
        );

        let result = dialer.connect(deadline()).await;

        assert!(matches!(result, Err(UpstreamError::Io(_))));
        assert!(!dialer.offers_full_suites());
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_alpn_protocol_follows_the_transport() {
        let pki = TestPki::new();
        let server = idle_server(&pki, &["h2", "dot"], ring::default_provider()).await;

        let h2 = dialer(&pki, true, Alpn::H2, &server)
            .connect(deadline())
            .await
            .unwrap();
        let dot = dialer(&pki, true, Alpn::Dot, &server)
            .connect(deadline())
            .await
            .unwrap();

        assert_eq!(h2.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        assert_eq!(dot.get_ref().1.alpn_protocol(), Some(&b"dot"[..]));
    }

    #[tokio::test]
    async fn an_ip_address_is_checked_against_the_ip_names_of_the_certificate() {
        let pki = TestPki::new();
        let server = idle_server(&pki, &["h2"], ring::default_provider()).await;
        let tls = Arc::new(Tls::with_roots(pki.roots(), true));
        let name = ServerName::try_from("127.0.0.1").unwrap();
        let dialer = TlsDialer::new(
            tls,
            Alpn::H2,
            name,
            Remote::at(server.address),
            "test".into(),
        );

        assert!(dialer.connect(deadline()).await.is_ok());
    }

    #[tokio::test]
    async fn the_built_in_roots_reject_a_test_certificate() {
        let pki = TestPki::new();
        let server = idle_server(&pki, &["h2"], ring::default_provider()).await;
        let tls = Arc::new(Tls::with_webpki_roots());
        let name = ServerName::try_from("localhost").unwrap();
        let dialer = TlsDialer::new(
            tls,
            Alpn::H2,
            name,
            Remote::at(server.address),
            "test".into(),
        );

        assert!(dialer.connect(deadline()).await.is_err());
    }

    #[test]
    fn the_aes_flag_is_read_from_cpuinfo_lines() {
        let arm_with = "processor : 0\nFeatures\t: half thumb fastmult vfp neon aes pmull sha1\n";
        let arm_without = "Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva\n";
        let x86_with = "flags\t\t: fpu vme sse4_2 aes avx\n";
        let lookalike = "flags : vaes aesni\nmodel name : aes machine\n";

        assert!(cpuinfo_lists_aes(arm_with));
        assert!(!cpuinfo_lists_aes(arm_without));
        assert!(cpuinfo_lists_aes(x86_with));
        assert!(!cpuinfo_lists_aes(lookalike));
        assert!(!cpuinfo_lists_aes(""));
    }

    #[test]
    fn each_alpn_and_suite_list_gets_its_own_cached_configuration() {
        let without_aes = Tls::with_roots(Arc::new(RootCertStore::empty()), false);

        let h2 = without_aes.config(Alpn::H2, false);
        let dot = without_aes.config(Alpn::Dot, false);
        let h2_full = without_aes.config(Alpn::H2, true);

        assert!(Arc::ptr_eq(&h2, &without_aes.config(Alpn::H2, false)));
        assert!(!Arc::ptr_eq(&h2, &dot));
        assert!(!Arc::ptr_eq(&h2, &h2_full));
        assert_eq!(h2.alpn_protocols, vec![b"h2".to_vec()]);
        assert_eq!(dot.alpn_protocols, vec![b"dot".to_vec()]);
    }
}
