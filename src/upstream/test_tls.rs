//! A local certificate authority and TLS server for the encrypted-transport
//! tests. Nothing here touches the network.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

pub struct TestPki {
    authority: CertifiedIssuer<'static, KeyPair>,
}

impl TestPki {
    pub fn new() -> TestPki {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let authority = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();

        TestPki { authority }
    }

    pub fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.authority.der().clone()).unwrap();

        Arc::new(roots)
    }

    /// A server configuration with a certificate for `localhost` and the
    /// loopback addresses, offering `alpn` and the cipher suites of `provider`.
    /// The server picks the cipher suite, not the client.
    pub fn server_config(&self, alpn: &[&str], provider: CryptoProvider) -> ServerConfig {
        self.server_config_for(rustls::ALL_VERSIONS, alpn, provider)
    }

    pub fn tls12_server_config(&self, alpn: &[&str], provider: CryptoProvider) -> ServerConfig {
        self.server_config_for(&[&rustls::version::TLS12], alpn, provider)
    }

    fn server_config_for(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[&str],
        provider: CryptoProvider,
    ) -> ServerConfig {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        for address in ["127.0.0.1", "::1"] {
            let address: IpAddr = address.parse().unwrap();
            params.subject_alt_names.push(SanType::IpAddress(address));
        }
        let certificate = params.signed_by(&key, &self.authority).unwrap();

        let chain: Vec<CertificateDer<'static>> = vec![certificate.der().clone()];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        config.ignore_client_order = true;
        config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();

        config
    }
}

/// Accepts TLS connections and hands each to a handler task. Stopping the
/// server closes the listener and every connection, which is how the tests
/// restart one.
pub struct TlsServer {
    pub address: SocketAddr,
    /// Accepted TCP connections, whether or not the handshake succeeded.
    pub connections: Arc<AtomicUsize>,
    /// Completed TLS handshakes.
    pub handshakes: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl TlsServer {
    pub async fn start<H, F>(config: ServerConfig, handler: H) -> TlsServer
    where
        H: Fn(TlsStream<TcpStream>) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        TlsServer::start_on(listener, config, handler)
    }

    pub fn start_on<H, F>(listener: TcpListener, config: ServerConfig, handler: H) -> TlsServer
    where
        H: Fn(TlsStream<TcpStream>) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let address = listener.local_addr().unwrap();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let (accepted, counter) = (Arc::clone(&connections), Arc::clone(&handshakes));
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let handler = Arc::new(handler);

        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();

            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let handler = Arc::clone(&handler);
                let counter = Arc::clone(&counter);

                connections.spawn(async move {
                    let Ok(stream) = acceptor.accept(tcp).await else {
                        return;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    handler(stream).await;
                });
            }
        });

        TlsServer {
            address,
            connections,
            handshakes,
            task,
        }
    }

    /// Waits until `count` handshakes have completed on the server side, which
    /// can lag behind the client by a moment.
    pub async fn wait_for_handshakes(&self, count: usize) {
        for _ in 0..200 {
            if self.handshakes.load(Ordering::SeqCst) >= count {
                return;
            }

            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
