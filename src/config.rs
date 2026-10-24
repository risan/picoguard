use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

const UPSTREAM_SCHEMES: [&str; 4] = ["https://", "tls://", "udp://", "tcp://"];
const LIST_URL_SCHEMES: [&str; 2] = ["http://", "https://"];
const MIN_UDP_SIZE: u16 = 512;
const MAX_UDP_SIZE: u16 = 4096;
const MAX_H2_WINDOW: u32 = (1 << 31) - 1;

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
            ConfigError::Parse(source) => write!(formatter, "{source}"),
            ConfigError::Invalid(message) => write!(formatter, "{message}"),
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
        self.state.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub udp_size: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind: Ipv4Addr::UNSPECIFIED.into(),
            port: 53,
            udp_size: 1232,
        }
    }
}

impl ServerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
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
            bootstrap: Vec::new(),
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
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
}

impl Default for ListConfig {
    fn default() -> Self {
        ListConfig {
            name: None,
            url: None,
            path: None,
            format: ListFormat::Auto,
            refresh_hours: 24,
            max_rules: 3_000_000,
            max_body_bytes: 64 * 1024 * 1024,
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
            (None, None) => return invalid(format!("{field}: set url or path")),
            (Some(url), None) => {
                if !LIST_URL_SCHEMES
                    .iter()
                    .any(|scheme| url.starts_with(scheme))
                {
                    return invalid(format!("{field}.url must start with http:// or https://"));
                }
            }
            (None, Some(_)) => {}
        }

        positive(&format!("{field}.refresh_hours"), self.refresh_hours)?;
        positive(&format!("{field}.max_rules"), self.max_rules)?;
        positive(&format!("{field}.max_body_bytes"), self.max_body_bytes)
    }
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
    pub bind: IpAddr,
    pub port: u16,
    pub hostnames: Vec<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub query_log_entries: usize,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            enabled: true,
            bind: Ipv4Addr::UNSPECIFIED.into(),
            port: 8080,
            hostnames: Vec::new(),
            user: None,
            password: None,
            query_log_entries: 1000,
        }
    }
}

impl WebConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match (&self.user, &self.password) {
            (Some(_), None) => return invalid("web.password must be set when web.user is set"),
            (None, Some(_)) => return invalid("web.user must be set when web.password is set"),
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

        positive("web.query_log_entries", self.query_log_entries)
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

fn invalid(message: impl Into<String>) -> Result<(), ConfigError> {
    Err(ConfigError::Invalid(message.into()))
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
            bind = "127.0.0.1"
            port = 5353
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
            bind = "192.168.1.2"
            port = 80
            hostnames = ["picoguard.lan"]
            user = "admin"
            password = "secret"

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
        assert_eq!(config.lists[1].refresh_hours, 24);
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
                "[web]\nquery_log_entries = 0",
                "web.query_log_entries must be > 0",
            ),
            ("[state]\ndir = \"\"", "state.dir must not be empty"),
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
    fn negative_number_is_rejected() {
        assert!(Config::parse("[cache]\nmax_entries = -1").is_err());
    }

    #[test]
    fn invalid_ip_address_is_rejected() {
        let message = error_of("[server]\nbind = \"not-an-ip\"");

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
