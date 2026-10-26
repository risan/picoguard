use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::filter::compile::DEFAULT_SLOW_RULE_BUDGET;
use crate::upstream::Upstreams;

const UPSTREAM_SCHEMES: [&str; 4] = ["https://", "tls://", "udp://", "tcp://"];
const LIST_URL_SCHEMES: [&str; 2] = ["http://", "https://"];
const MIN_UDP_SIZE: u16 = 512;
const MAX_UDP_SIZE: u16 = 4096;
const MAX_H2_WINDOW: u32 = (1 << 31) - 1;
const MAX_QUERY_LOG_ENTRIES: usize = 100_000;
const MAX_TOP_K: usize = 1000;

/// Networks that may talk to picoguard: loopback, private ranges, CGNAT
/// (which covers Tailscale) and link-local.
const DEFAULT_ALLOW_FROM: [&str; 9] = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];

/// An IP network such as `192.168.0.0/16`. A bare address means one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    pub fn contains(&self, address: IpAddr) -> bool {
        if let (IpAddr::V4(network), IpAddr::V4(address)) = (self.network, address.to_canonical()) {
            let mask = v4_mask(self.prefix_len);

            return u32::from(network) & mask == u32::from(address) & mask;
        }

        if let (IpAddr::V6(network), IpAddr::V6(address)) = (self.network, address.to_canonical()) {
            let mask = v6_mask(self.prefix_len);

            return u128::from(network) & mask == u128::from(address) & mask;
        }

        false
    }
}

fn v4_mask(prefix_len: u8) -> u32 {
    u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0)
}

fn v6_mask(prefix_len: u8) -> u128 {
    u128::MAX
        .checked_shl(128 - u32::from(prefix_len))
        .unwrap_or(0)
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(text: &str) -> Result<Cidr, String> {
        let invalid = |reason: &str| format!("invalid network {text:?}: {reason}");
        let (address, prefix) = text
            .split_once('/')
            .map_or((text, None), |(address, prefix)| (address, Some(prefix)));
        let address: IpAddr = address.parse().map_err(|_| invalid("not an IP address"))?;
        let max_prefix_len = if address.is_ipv4() { 32 } else { 128 };

        let mut prefix_len = max_prefix_len;
        if let Some(prefix) = prefix {
            prefix_len = prefix
                .parse::<u8>()
                .map_err(|_| invalid("prefix length is not a number"))?;
        }

        if prefix_len > max_prefix_len {
            return Err(invalid(&format!("prefix length is above {max_prefix_len}")));
        }

        let network = match address {
            IpAddr::V4(address) => {
                let masked = u32::from(address) & v4_mask(prefix_len);

                IpAddr::V4(masked.into())
            }

            IpAddr::V6(address) => {
                let masked = u128::from(address) & v6_mask(prefix_len);

                IpAddr::V6(masked.into())
            }
        };

        Ok(Cidr {
            network,
            prefix_len,
        })
    }
}

impl TryFrom<String> for Cidr {
    type Error = String;

    fn try_from(text: String) -> Result<Cidr, String> {
        text.parse()
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_len)
    }
}

/// True when `address` is in one of the networks.
pub fn is_allowed(allowed: &[Cidr], address: IpAddr) -> bool {
    allowed.iter().any(|network| network.contains(address))
}

fn default_allow_from() -> Vec<Cidr> {
    DEFAULT_ALLOW_FROM
        .iter()
        .map(|text| text.parse().expect("default network is valid"))
        .collect()
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse(toml::de::Error),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read { path, source } => {
                write!(formatter, "cannot read {}: {source}", path.display())
            }

            ConfigError::Parse(source) => {
                write!(formatter, "{source}")
            }

            ConfigError::Invalid(message) => {
                write!(formatter, "{message}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub local: LocalConfig,
    pub lists: Vec<ListConfig>,
    pub rules: Vec<String>,
    pub allowlists: Vec<ListConfig>,
    pub cache: CacheConfig,
    pub limits: LimitsConfig,
    pub web: WebConfig,
    pub stats: StatsConfig,
    pub state: StateConfig,
    pub log: LogConfig,
    pub blocked_ttl: u32,
    pub blocked_hosts: Vec<String>,
    pub refuse_any: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig::default(),
            upstream: UpstreamConfig::default(),
            local: LocalConfig::default(),
            lists: vec![
                ListConfig::adblock(
                    "adguard-dns",
                    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
                ),
                ListConfig::adblock(
                    "hagezi-pro",
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
                ),
                ListConfig::adblock(
                    "hagezi-tif-mini",
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt",
                ),
            ],
            rules: Vec::new(),
            allowlists: Vec::new(),
            cache: CacheConfig::default(),
            limits: LimitsConfig::default(),
            web: WebConfig::default(),
            stats: StatsConfig::default(),
            state: StateConfig::default(),
            log: LogConfig::default(),
            blocked_ttl: 10,
            blocked_hosts: ["version.bind", "id.server", "hostname.bind"]
                .map(String::from)
                .to_vec(),
            refuse_any: true,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        Config::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let config: Config = toml::from_str(text).map_err(ConfigError::Parse)?;
        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.server.validate()?;
        self.upstream.validate()?;
        self.local.validate()?;
        validate_lists("lists", &self.lists)?;
        validate_lists("allowlists", &self.allowlists)?;
        self.cache.validate()?;
        self.limits.validate()?;
        self.web.validate()?;
        self.stats.validate()?;
        self.state.validate()?;

        // What the server would stop at when it starts.
        Upstreams::from_config(&self.upstream, &self.limits).map_err(ConfigError::Invalid)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: Vec<IpAddr>,
    pub port: u16,
    pub udp_size: u16,
    pub allow_from: Vec<Cidr>,
}

fn default_bind() -> Vec<IpAddr> {
    vec![Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()]
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind: default_bind(),
            port: 53,
            udp_size: 1232,
            allow_from: default_allow_from(),
        }
    }
}

impl ServerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_listen("server", &self.bind, &self.allow_from)?;

        if !(MIN_UDP_SIZE..=MAX_UDP_SIZE).contains(&self.udp_size) {
            return invalid(format!(
                "server.udp_size must be between {MIN_UDP_SIZE} and {MAX_UDP_SIZE}"
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    pub servers: Vec<String>,
    pub bootstrap: Vec<IpAddr>,
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        UpstreamConfig {
            servers: [
                "https://1.1.1.1/dns-query",
                "https://1.0.0.1/dns-query",
                "https://9.9.9.10/dns-query",
                "https://149.112.112.10/dns-query",
            ]
            .map(String::from)
            .to_vec(),
            bootstrap: ["9.9.9.9", "1.1.1.1"]
                .map(|address| address.parse().expect("bootstrap address is valid"))
                .to_vec(),
            timeout_ms: 5000,
        }
    }
}

impl UpstreamConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.servers.is_empty() {
            return invalid("upstream.servers must not be empty");
        }

        for (index, server) in self.servers.iter().enumerate() {
            if !UPSTREAM_SCHEMES
                .iter()
                .any(|scheme| server.starts_with(scheme))
            {
                return invalid(format!(
                    "upstream.servers[{index}] must start with one of {}",
                    UPSTREAM_SCHEMES.join(", ")
                ));
            }
        }

        positive("upstream.timeout_ms", self.timeout_ms)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalConfig {
    pub resolver: Option<SocketAddr>,
    pub domains: Vec<String>,
}

impl LocalConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for (index, domain) in self.domains.iter().enumerate() {
            if domain.is_empty() || domain.contains(char::is_whitespace) {
                return invalid(format!(
                    "local.domains[{index}] must be a domain name without spaces"
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListFormat {
    #[default]
    Auto,
    Adblock,
    Hosts,
    Domains,
    Wildcard,
    Dnsmasq,
    Rpz,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListConfig {
    pub name: Option<String>,
    pub url: Option<String>,
    pub path: Option<PathBuf>,
    pub format: ListFormat,
    pub refresh_hours: u32,
    pub max_rules: u32,
    pub max_body_bytes: u64,
    /// Estimated bytes the slow rules and regexes of the list may cost.
    pub slow_rule_budget: usize,
    /// Lets a downloaded list answer a name with the IP of its hosts line. Without it any IP
    /// but 0.0.0.0, ::, 127.0.0.1 and ::1 blocks like 0.0.0.0. Local files always may.
    pub allow_redirects: bool,
}

impl Default for ListConfig {
    fn default() -> Self {
        ListConfig {
            name: None,
            url: None,
            path: None,
            format: ListFormat::Auto,
            refresh_hours: 24,
            max_rules: 1_500_000,
            max_body_bytes: 64 * 1024 * 1024,
            slow_rule_budget: DEFAULT_SLOW_RULE_BUDGET,
            allow_redirects: false,
        }
    }
}

impl ListConfig {
    fn adblock(name: &str, url: &str) -> ListConfig {
        ListConfig {
            name: Some(name.to_string()),
            url: Some(url.to_string()),
            format: ListFormat::Adblock,
            ..ListConfig::default()
        }
    }

    fn validate(&self, field: &str) -> Result<(), ConfigError> {
        match (&self.url, &self.path) {
            (Some(_), Some(_)) => {
                return invalid(format!("{field}: set either url or path, not both"));
            }

            (None, None) => {
                return invalid(format!("{field}: set url or path"));
            }

            (Some(url), None) => {
                let Some(rest) = LIST_URL_SCHEMES
                    .iter()
                    .find_map(|scheme| url.strip_prefix(scheme))
                else {
                    return invalid(format!("{field}.url must start with http:// or https://"));
                };

                if !has_host(rest) {
                    return invalid(format!("{field}.url has no host"));
                }
            }

            (None, Some(path)) => {
                if path.as_os_str().is_empty() {
                    return invalid(format!("{field}.path must not be empty"));
                }
            }
        }

        positive(&format!("{field}.refresh_hours"), self.refresh_hours)?;
        positive(&format!("{field}.max_rules"), self.max_rules)?;
        positive(&format!("{field}.max_body_bytes"), self.max_body_bytes)?;
        positive(&format!("{field}.slow_rule_budget"), self.slow_rule_budget)
    }
}

fn has_host(url_after_scheme: &str) -> bool {
    let authority = url_after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host_and_port = authority.rsplit('@').next().unwrap_or_default();
    let host = if let Some(bracketed) = host_and_port.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        host_and_port.split(':').next().unwrap_or_default()
    };

    !host.is_empty() && !host.contains(char::is_whitespace)
}

fn validate_lists(section: &str, lists: &[ListConfig]) -> Result<(), ConfigError> {
    for (index, list) in lists.iter().enumerate() {
        list.validate(&format!("{section}[{index}]"))?;
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub max_response_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: 10_000,
            max_bytes: 4 * 1024 * 1024,
            min_ttl: 0,
            max_ttl: 86_400,
            max_response_size: 4096,
        }
    }
}

impl CacheConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        positive("cache.max_entries", self.max_entries)?;
        positive("cache.max_bytes", self.max_bytes)?;
        positive("cache.max_ttl", self.max_ttl)?;
        positive("cache.max_response_size", self.max_response_size)?;

        if self.min_ttl > self.max_ttl {
            return invalid("cache.min_ttl must be <= cache.max_ttl");
        }

        if self.max_response_size > usize::from(u16::MAX) {
            return invalid("cache.max_response_size must be <= 65535");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub h2_stream_window: u32,
    pub h2_connection_window: u32,
    pub h2_max_header_list: u32,
    pub upstream_concurrency: usize,
    pub max_inflight_queries: usize,
    pub max_waiting_clients: usize,
    pub tcp_max_connections: usize,
    pub tcp_idle_secs: u64,
    pub tcp_read_buffer: usize,
    pub tcp_queue_replies: usize,
    pub tcp_queue_bytes: usize,
    pub tcp_write_timeout_secs: u64,
    pub upstream_reply_max: usize,
    pub pending_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            h2_stream_window: 64 * 1024,
            h2_connection_window: 128 * 1024,
            h2_max_header_list: 16 * 1024,
            upstream_concurrency: 32,
            max_inflight_queries: 128,
            max_waiting_clients: 256,
            tcp_max_connections: 16,
            tcp_idle_secs: 30,
            tcp_read_buffer: 2048,
            tcp_queue_replies: 4,
            tcp_queue_bytes: 128 * 1024,
            tcp_write_timeout_secs: 5,
            upstream_reply_max: 64 * 1024,
            pending_bytes: 1024 * 1024,
        }
    }
}

impl LimitsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        positive("limits.h2_stream_window", self.h2_stream_window)?;
        positive("limits.h2_connection_window", self.h2_connection_window)?;
        positive("limits.h2_max_header_list", self.h2_max_header_list)?;
        positive("limits.upstream_concurrency", self.upstream_concurrency)?;
        positive("limits.max_inflight_queries", self.max_inflight_queries)?;
        positive("limits.max_waiting_clients", self.max_waiting_clients)?;
        positive("limits.tcp_max_connections", self.tcp_max_connections)?;
        positive("limits.tcp_idle_secs", self.tcp_idle_secs)?;
        positive("limits.tcp_read_buffer", self.tcp_read_buffer)?;
        positive("limits.tcp_queue_replies", self.tcp_queue_replies)?;
        positive("limits.tcp_queue_bytes", self.tcp_queue_bytes)?;
        positive("limits.tcp_write_timeout_secs", self.tcp_write_timeout_secs)?;
        positive("limits.upstream_reply_max", self.upstream_reply_max)?;
        positive("limits.pending_bytes", self.pending_bytes)?;

        for (field, window) in [
            ("limits.h2_stream_window", self.h2_stream_window),
            ("limits.h2_connection_window", self.h2_connection_window),
        ] {
            if window > MAX_H2_WINDOW {
                return invalid(format!("{field} must be <= {MAX_H2_WINDOW}"));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    pub enabled: bool,
    pub bind: Vec<IpAddr>,
    pub port: u16,
    pub allow_from: Vec<Cidr>,
    pub hostnames: Vec<String>,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            enabled: true,
            bind: default_bind(),
            port: 8080,
            allow_from: default_allow_from(),
            hostnames: Vec::new(),
            user: None,
            password: None,
        }
    }
}

impl WebConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_listen("web", &self.bind, &self.allow_from)?;

        match (&self.user, &self.password) {
            (Some(_), None) => {
                return invalid("web.password must be set when web.user is set");
            }

            (None, Some(_)) => {
                return invalid("web.user must be set when web.password is set");
            }

            (Some(user), Some(password)) => {
                if user.is_empty() || user.contains(':') {
                    return invalid("web.user must not be empty or contain ':'");
                }

                if password.is_empty() {
                    return invalid("web.password must not be empty");
                }
            }

            (None, None) => {}
        }

        Ok(())
    }
}

/// Sizes of the statistics. Both are allocated in full, so they have an upper bound.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StatsConfig {
    pub query_log_entries: usize,
    pub top_k: usize,
}

impl Default for StatsConfig {
    fn default() -> Self {
        StatsConfig {
            query_log_entries: 1000,
            top_k: 50,
        }
    }
}

impl StatsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        in_range(
            "stats.query_log_entries",
            self.query_log_entries,
            MAX_QUERY_LOG_ENTRIES,
        )?;

        in_range("stats.top_k", self.top_k, MAX_TOP_K)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StateConfig {
    pub dir: PathBuf,
    pub persist_lists: bool,
}

impl Default for StateConfig {
    fn default() -> Self {
        StateConfig {
            dir: PathBuf::from("/var/lib/picoguard"),
            persist_lists: true,
        }
    }
}

impl StateConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.dir.as_os_str().is_empty() {
            return invalid("state.dir must not be empty");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    #[default]
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    pub level: LogLevel,
}

fn validate_listen(section: &str, bind: &[IpAddr], allow_from: &[Cidr]) -> Result<(), ConfigError> {
    if bind.is_empty() {
        return invalid(format!("{section}.bind must not be empty"));
    }

    if allow_from.is_empty() {
        return invalid(format!(
            "{section}.allow_from must not be empty, use [\"0.0.0.0/0\", \"::/0\"] to allow everyone"
        ));
    }

    Ok(())
}

fn invalid(message: impl Into<String>) -> Result<(), ConfigError> {
    Err(ConfigError::Invalid(message.into()))
}

fn in_range(field: &str, value: usize, max: usize) -> Result<(), ConfigError> {
    positive(field, value)?;

    if value > max {
        return invalid(format!("{field} must be <= {max}"));
    }

    Ok(())
}

fn positive<T: Default + PartialOrd>(field: &str, value: T) -> Result<(), ConfigError> {
    if value > T::default() {
        return Ok(());
    }

    invalid(format!("{field} must be > 0"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_CONFIG: &str = include_str!("../dist/picoguard.toml");

    fn error_of(text: &str) -> String {
        Config::parse(text)
            .expect_err("config should be rejected")
            .to_string()
    }

    #[test]
    fn empty_config_equals_defaults() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
    }

    #[test]
    fn the_default_bootstrap_is_the_documented_one() {
        let expected: Vec<IpAddr> = vec!["9.9.9.9".parse().unwrap(), "1.1.1.1".parse().unwrap()];

        assert_eq!(Config::default().upstream.bootstrap, expected);
        assert!(EXAMPLE_CONFIG.contains(r#"# bootstrap = ["9.9.9.9", "1.1.1.1"]"#));
    }

    #[test]
    fn an_upstream_that_cannot_be_built_is_rejected_with_the_config() {
        let cases = [
            (
                "[upstream]\nservers = [\"https://dns.example/dns-query\"]\nbootstrap = []",
                "upstream.bootstrap",
            ),
            (
                "[upstream]\nservers = [\"tls://dns.example\"]\nbootstrap = []",
                "upstream.bootstrap",
            ),
            (
                "[upstream]\nservers = [\"udp://dns.example\"]",
                "IP address",
            ),
            (
                "[upstream]\nservers = [\"tls://1.1.1.1#not a name\"]",
                "server name",
            ),
        ];

        for (text, expected) in cases {
            let message = error_of(text);

            assert!(message.contains(expected), "{text}: {message}");
        }
    }

    #[test]
    fn a_host_name_upstream_is_accepted_with_the_default_bootstrap() {
        let config = Config::parse(
            "[upstream]\nservers = [\"https://unfiltered.adguard-dns.com/dns-query\"]",
        );

        assert!(config.is_ok(), "{config:?}");
    }

    #[test]
    fn defaults_match_the_plan() {
        let config = Config::default();

        assert_eq!(config.server.port, 53);
        assert_eq!(config.blocked_ttl, 10);
        assert!(config.refuse_any);
        assert_eq!(
            config.blocked_hosts,
            ["version.bind", "id.server", "hostname.bind"]
        );
        assert_eq!(config.cache.max_entries, 10_000);
        assert_eq!(config.cache.max_bytes, 4 * 1024 * 1024);
        assert_eq!(config.cache.max_response_size, 4096);
        assert_eq!(config.stats.query_log_entries, 1000);
        assert_eq!(config.stats.top_k, 50);
        assert_eq!(config.log.level, LogLevel::Warn);
        assert!(config.state.persist_lists);
        assert!(config.rules.is_empty());
        assert!(config.allowlists.is_empty());
        assert!(config.local.resolver.is_none());
        assert!(config.web.user.is_none());
        assert!(config.web.password.is_none());
    }

    #[test]
    fn default_limits_match_d21() {
        let limits = LimitsConfig::default();

        assert_eq!(limits.h2_stream_window, 64 * 1024);
        assert_eq!(limits.h2_connection_window, 128 * 1024);
        assert_eq!(limits.h2_max_header_list, 16 * 1024);
        assert_eq!(limits.upstream_concurrency, 32);
        assert_eq!(limits.max_inflight_queries, 128);
        assert_eq!(limits.max_waiting_clients, 256);
        assert_eq!(limits.tcp_max_connections, 16);
        assert_eq!(limits.tcp_idle_secs, 30);
        assert_eq!(limits.tcp_read_buffer, 2048);
        assert_eq!(limits.tcp_queue_replies, 4);
        assert_eq!(limits.tcp_queue_bytes, 128 * 1024);
        assert_eq!(limits.tcp_write_timeout_secs, 5);
        assert_eq!(limits.upstream_reply_max, 64 * 1024);
        assert_eq!(limits.pending_bytes, 1024 * 1024);
    }

    #[test]
    fn default_lists_and_upstreams_match_the_brief() {
        let config = Config::default();

        let urls: Vec<_> = config
            .lists
            .iter()
            .map(|list| list.url.as_deref())
            .collect();
        assert_eq!(
            urls,
            [
                Some("https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"),
                Some(
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
                ),
                Some(
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt"
                ),
            ]
        );
        assert!(
            config
                .lists
                .iter()
                .all(|list| list.format == ListFormat::Adblock)
        );
        assert!(config.lists.iter().all(|list| list.refresh_hours == 24));
        assert!(
            config
                .lists
                .iter()
                .all(|list| list.slow_rule_budget == 8 * 1024 * 1024)
        );
        assert!(config.lists.iter().all(|list| list.max_rules == 1_500_000));
        assert_eq!(
            config.upstream.servers,
            [
                "https://1.1.1.1/dns-query",
                "https://1.0.0.1/dns-query",
                "https://9.9.9.10/dns-query",
                "https://149.112.112.10/dns-query",
            ]
        );
    }

    #[test]
    fn default_config_is_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn example_config_parses_and_equals_defaults() {
        assert_eq!(Config::parse(EXAMPLE_CONFIG).unwrap(), Config::default());
    }

    #[test]
    fn full_config_parses() {
        let config = Config::parse(
            r#"
            blocked_ttl = 30
            refuse_any = false
            blocked_hosts = ["bind.example"]
            rules = ["||ads.example^", "@@||ok.example^"]

            [server]
            bind = ["127.0.0.1", "::1"]
            port = 5353
            allow_from = ["192.168.1.0/24", "10.1.2.3"]
            udp_size = 1400

            [upstream]
            servers = ["tls://9.9.9.9#dns.quad9.net", "udp://192.168.1.1:53"]
            bootstrap = ["9.9.9.9", "2620:fe::fe"]
            timeout_ms = 2000

            [local]
            resolver = "192.168.1.1:53"
            domains = ["lan"]

            [[lists]]
            url = "http://example.com/hosts.txt"
            format = "hosts"
            refresh_hours = 6
            max_rules = 1000
            max_body_bytes = 1048576
            slow_rule_budget = 1048576
            allow_redirects = true

            [[lists]]
            path = "/etc/picoguard/mine.txt"

            [[allowlists]]
            path = "/etc/picoguard/allow.txt"

            [cache]
            max_entries = 500
            max_bytes = 65536
            min_ttl = 10
            max_ttl = 3600
            max_response_size = 1232

            [web]
            enabled = false
            bind = ["192.168.1.2"]
            port = 80
            hostnames = ["picoguard.lan"]
            user = "admin"
            password = "secret"

            [stats]
            query_log_entries = 200
            top_k = 20

            [state]
            dir = "/tmp/picoguard"
            persist_lists = false

            [log]
            level = "debug"
            "#,
        )
        .unwrap();

        assert_eq!(config.blocked_ttl, 30);
        assert_eq!(config.server.port, 5353);
        assert_eq!(config.upstream.bootstrap.len(), 2);
        assert_eq!(
            config.local.resolver,
            Some("192.168.1.1:53".parse().unwrap())
        );
        assert_eq!(config.lists.len(), 2);
        assert_eq!(config.lists[0].format, ListFormat::Hosts);
        assert_eq!(config.lists[1].format, ListFormat::Auto);
        assert_eq!(config.lists[0].slow_rule_budget, 1_048_576);
        assert!(config.lists[0].allow_redirects);
        assert!(!config.lists[1].allow_redirects);
        assert_eq!(config.lists[1].refresh_hours, 24);
        assert_eq!(config.stats.query_log_entries, 200);
        assert_eq!(config.stats.top_k, 20);
        assert_eq!(config.allowlists.len(), 1);
        assert_eq!(config.cache.max_ttl, 3600);
        assert_eq!(config.web.user.as_deref(), Some("admin"));
        assert!(!config.state.persist_lists);
        assert_eq!(config.log.level, LogLevel::Debug);
    }

    #[test]
    fn every_list_format_is_accepted() {
        for format in [
            "auto", "adblock", "hosts", "domains", "wildcard", "dnsmasq", "rpz",
        ] {
            let text = format!("[[lists]]\nurl = \"https://example.com/l\"\nformat = \"{format}\"");

            Config::parse(&text).unwrap();
        }
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let message = error_of("blocked_tll = 5");

        assert!(message.contains("blocked_tll"), "{message}");
    }

    #[test]
    fn unknown_section_key_is_rejected() {
        let message = error_of("[cache]\nmax_entires = 5");

        assert!(message.contains("max_entires"), "{message}");
    }

    #[test]
    fn unknown_list_key_is_rejected() {
        let message = error_of("[[lists]]\nurl = \"https://example.com/l\"\nfromat = \"hosts\"");

        assert!(message.contains("fromat"), "{message}");
    }

    #[test]
    fn unknown_list_format_is_rejected() {
        let message = error_of("[[lists]]\nurl = \"https://example.com/l\"\nformat = \"csv\"");

        assert!(message.contains("csv"), "{message}");
    }

    #[test]
    fn invalid_toml_is_rejected() {
        assert!(Config::parse("[cache").is_err());
    }

    #[test]
    fn invalid_values_are_rejected_with_the_field_name() {
        let cases = [
            (
                "[server]\nudp_size = 100",
                "server.udp_size must be between 512 and 4096",
            ),
            (
                "[server]\nudp_size = 9000",
                "server.udp_size must be between 512 and 4096",
            ),
            (
                "[upstream]\nservers = []",
                "upstream.servers must not be empty",
            ),
            (
                "[upstream]\nservers = [\"https://1.1.1.1/dns-query\", \"1.1.1.1\"]",
                "upstream.servers[1] must start with one of",
            ),
            (
                "[upstream]\ntimeout_ms = 0",
                "upstream.timeout_ms must be > 0",
            ),
            (
                "[local]\ndomains = [\"\"]",
                "local.domains[0] must be a domain name",
            ),
            (
                "[local]\ndomains = [\"a b\"]",
                "local.domains[0] must be a domain name",
            ),
            ("[[lists]]\nname = \"x\"", "lists[0]: set url or path"),
            (
                "[[lists]]\nurl = \"https://e.com/l\"\npath = \"/l\"",
                "lists[0]: set either url or path, not both",
            ),
            (
                "[[lists]]\nurl = \"https://e.com/a\"\n[[lists]]\nurl = \"ftp://e.com/l\"",
                "lists[1].url must start with http:// or https://",
            ),
            (
                "[[lists]]\npath = \"/l\"\nrefresh_hours = 0",
                "lists[0].refresh_hours must be > 0",
            ),
            (
                "[[lists]]\npath = \"/l\"\nmax_rules = 0",
                "lists[0].max_rules must be > 0",
            ),
            (
                "[[lists]]\npath = \"/l\"\nmax_body_bytes = 0",
                "lists[0].max_body_bytes must be > 0",
            ),
            (
                "[[allowlists]]\nformat = \"hosts\"",
                "allowlists[0]: set url or path",
            ),
            ("[cache]\nmax_entries = 0", "cache.max_entries must be > 0"),
            ("[cache]\nmax_bytes = 0", "cache.max_bytes must be > 0"),
            ("[cache]\nmax_ttl = 0", "cache.max_ttl must be > 0"),
            (
                "[cache]\nmin_ttl = 100\nmax_ttl = 50",
                "cache.min_ttl must be <= cache.max_ttl",
            ),
            (
                "[cache]\nmax_response_size = 0",
                "cache.max_response_size must be > 0",
            ),
            (
                "[cache]\nmax_response_size = 70000",
                "cache.max_response_size must be <= 65535",
            ),
            (
                "[limits]\nh2_stream_window = 0",
                "limits.h2_stream_window must be > 0",
            ),
            (
                "[limits]\nh2_connection_window = 4294967295",
                "limits.h2_connection_window must be <= 2147483647",
            ),
            (
                "[limits]\nh2_max_header_list = 0",
                "limits.h2_max_header_list must be > 0",
            ),
            (
                "[limits]\nupstream_concurrency = 0",
                "limits.upstream_concurrency must be > 0",
            ),
            (
                "[limits]\nmax_inflight_queries = 0",
                "limits.max_inflight_queries must be > 0",
            ),
            (
                "[limits]\nmax_waiting_clients = 0",
                "limits.max_waiting_clients must be > 0",
            ),
            (
                "[limits]\ntcp_max_connections = 0",
                "limits.tcp_max_connections must be > 0",
            ),
            (
                "[limits]\ntcp_idle_secs = 0",
                "limits.tcp_idle_secs must be > 0",
            ),
            (
                "[limits]\ntcp_read_buffer = 0",
                "limits.tcp_read_buffer must be > 0",
            ),
            (
                "[limits]\ntcp_queue_replies = 0",
                "limits.tcp_queue_replies must be > 0",
            ),
            (
                "[limits]\ntcp_queue_bytes = 0",
                "limits.tcp_queue_bytes must be > 0",
            ),
            (
                "[limits]\ntcp_write_timeout_secs = 0",
                "limits.tcp_write_timeout_secs must be > 0",
            ),
            (
                "[limits]\nupstream_reply_max = 0",
                "limits.upstream_reply_max must be > 0",
            ),
            (
                "[limits]\npending_bytes = 0",
                "limits.pending_bytes must be > 0",
            ),
            (
                "[web]\nuser = \"admin\"",
                "web.password must be set when web.user is set",
            ),
            (
                "[web]\npassword = \"secret\"",
                "web.user must be set when web.password is set",
            ),
            (
                "[web]\nuser = \"\"\npassword = \"secret\"",
                "web.user must not be empty or contain ':'",
            ),
            (
                "[web]\nuser = \"a:b\"\npassword = \"secret\"",
                "web.user must not be empty or contain ':'",
            ),
            (
                "[web]\nuser = \"admin\"\npassword = \"\"",
                "web.password must not be empty",
            ),
            (
                "[stats]\nquery_log_entries = 0",
                "stats.query_log_entries must be > 0",
            ),
            (
                "[stats]\nquery_log_entries = 100001",
                "stats.query_log_entries must be <= 100000",
            ),
            ("[stats]\ntop_k = 0", "stats.top_k must be > 0"),
            ("[stats]\ntop_k = 1001", "stats.top_k must be <= 1000"),
            (
                "[web]\nquery_log_entries = 10",
                "unknown field `query_log_entries`",
            ),
            (
                "[[lists]]\npath = \"/l\"\nslow_rule_budget = 0",
                "lists[0].slow_rule_budget must be > 0",
            ),
            (
                "[[allowlists]]\npath = \"/l\"\nslow_rule_budget = 0",
                "allowlists[0].slow_rule_budget must be > 0",
            ),
            ("[state]\ndir = \"\"", "state.dir must not be empty"),
            ("[[lists]]\npath = \"\"", "lists[0].path must not be empty"),
            ("[[lists]]\nurl = \"https://\"", "lists[0].url has no host"),
            (
                "[[lists]]\nurl = \"http:///list.txt\"",
                "lists[0].url has no host",
            ),
            (
                "[[lists]]\nurl = \"https://user@:8080/x\"",
                "lists[0].url has no host",
            ),
            (
                "[[allowlists]]\npath = \"\"",
                "allowlists[0].path must not be empty",
            ),
            (
                "[[allowlists]]\nurl = \"https://\"",
                "allowlists[0].url has no host",
            ),
        ];

        for (text, expected) in cases {
            let message = error_of(text);

            assert!(
                message.contains(expected),
                "config {text:?}: expected {expected:?}, got {message:?}"
            );
        }
    }

    #[test]
    fn urls_with_a_host_are_accepted() {
        for url in [
            "https://example.com/list.txt",
            "http://192.168.1.2:8080/l",
            "https://user:pw@example.com/l",
            "https://[2001:db8::1]:443/l",
            "https://example.com",
        ] {
            let text = format!("[[lists]]\nurl = \"{url}\"");

            Config::parse(&text).unwrap();
        }
    }

    #[test]
    fn web_bind_defaults_to_both_families() {
        assert_eq!(
            Config::default().web.bind,
            ["0.0.0.0".parse::<IpAddr>().unwrap(), "::".parse().unwrap()]
        );
    }

    #[test]
    fn web_bind_accepts_ipv4_only_and_ipv6_only() {
        let ipv4 = Config::parse("[web]\nbind = [\"127.0.0.1\"]").unwrap();
        let ipv6 = Config::parse("[web]\nbind = [\"::1\"]").unwrap();

        assert_eq!(ipv4.web.bind, ["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(ipv6.web.bind, ["::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn cidr_matches_networks_and_single_hosts() {
        let lan: Cidr = "192.168.0.0/16".parse().unwrap();
        let host: Cidr = "10.1.2.3".parse().unwrap();
        let v6: Cidr = "fc00::/7".parse().unwrap();
        let everything: Cidr = "0.0.0.0/0".parse().unwrap();
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();

        assert!(lan.contains(ip("192.168.255.1")));
        assert!(!lan.contains(ip("192.169.0.1")));
        assert!(host.contains(ip("10.1.2.3")));
        assert!(!host.contains(ip("10.1.2.4")));
        assert!(v6.contains(ip("fd12:3456::1")));
        assert!(!v6.contains(ip("fe80::1")));
        assert!(everything.contains(ip("8.8.8.8")));
        assert!(!everything.contains(ip("::1")), "families do not mix");
        assert_eq!(lan.to_string(), "192.168.0.0/16");
    }

    #[test]
    fn cidr_treats_an_ipv4_mapped_address_as_ipv4() {
        let lan: Cidr = "192.168.0.0/16".parse().unwrap();

        assert!(lan.contains("::ffff:192.168.1.1".parse().unwrap()));
        assert!(!lan.contains("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_masks_host_bits_of_the_network() {
        let cidr: Cidr = "10.9.8.7/8".parse().unwrap();

        assert_eq!(cidr.to_string(), "10.0.0.0/8");
        assert!(cidr.contains("10.200.0.1".parse().unwrap()));
    }

    #[test]
    fn invalid_cidrs_are_rejected() {
        for text in [
            "",
            "lan",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/x",
            "10.0.0.0/-1",
            "/8",
        ] {
            assert!(text.parse::<Cidr>().is_err(), "{text:?} was accepted");
        }
    }

    #[test]
    fn default_access_lists_cover_private_ranges_only() {
        let config = Config::default();
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();

        for allowed in [
            "127.0.0.1",
            "::1",
            "10.2.3.4",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(
                is_allowed(&config.server.allow_from, ip(allowed)),
                "{allowed}"
            );
            assert!(is_allowed(&config.web.allow_from, ip(allowed)), "{allowed}");
        }

        for denied in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "192.169.0.1",
            "2001:db8::1",
            "fec0::1",
        ] {
            assert!(
                !is_allowed(&config.server.allow_from, ip(denied)),
                "{denied}"
            );
            assert!(!is_allowed(&config.web.allow_from, ip(denied)), "{denied}");
        }
    }

    #[test]
    fn server_bind_defaults_to_both_families_and_accepts_one_family() {
        let both = ["0.0.0.0".parse::<IpAddr>().unwrap(), "::".parse().unwrap()];
        let ipv4 = Config::parse("[server]\nbind = [\"127.0.0.1\"]").unwrap();
        let ipv6 = Config::parse("[server]\nbind = [\"::1\"]").unwrap();

        assert_eq!(Config::default().server.bind, both);
        assert_eq!(ipv4.server.bind, ["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(ipv6.server.bind, ["::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn allow_from_is_read_from_both_sections() {
        let config = Config::parse(
            "[server]\nallow_from = [\"203.0.113.0/24\"]\n[web]\nallow_from = [\"::1\"]",
        )
        .unwrap();

        assert_eq!(config.server.allow_from.len(), 1);
        assert!(is_allowed(
            &config.server.allow_from,
            "203.0.113.9".parse().unwrap()
        ));
        assert!(!is_allowed(
            &config.server.allow_from,
            "127.0.0.1".parse().unwrap()
        ));
        assert!(is_allowed(&config.web.allow_from, "::1".parse().unwrap()));
    }

    #[test]
    fn bad_listen_settings_are_rejected_with_the_field_name() {
        let cases = [
            ("[server]\nbind = []", "server.bind must not be empty"),
            ("[web]\nbind = []", "web.bind must not be empty"),
            (
                "[server]\nallow_from = []",
                "server.allow_from must not be empty",
            ),
            ("[web]\nallow_from = []", "web.allow_from must not be empty"),
            (
                "[server]\nallow_from = [\"10.0.0.0/40\"]",
                "prefix length is above 32",
            ),
            ("[web]\nallow_from = [\"lan\"]", "not an IP address"),
        ];

        for (text, expected) in cases {
            let message = error_of(text);

            assert!(message.contains(expected), "{text:?}: {message}");
        }
    }

    #[test]
    fn negative_number_is_rejected() {
        assert!(Config::parse("[cache]\nmax_entries = -1").is_err());
    }

    #[test]
    fn invalid_ip_address_is_rejected() {
        let message = error_of("[server]\nbind = [\"not-an-ip\"]");

        assert!(message.contains("invalid IP address"), "{message}");
    }

    #[test]
    fn missing_file_names_the_path() {
        let error = Config::load(Path::new("/nonexistent/picoguard.toml")).unwrap_err();

        assert!(
            error.to_string().contains("/nonexistent/picoguard.toml"),
            "{error}"
        );
    }
}
