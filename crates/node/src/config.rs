//! Node configuration.
//!
//! A few knobs stay as environment variables (`SIKKA_PRIVATE_KEY`,
//! `SIKKA_ADVERTISE`, …). Paths, listen port, and “act as a validator” are
//! fixed so a normal `docker run` does not ask the operator to invent
//! filesystem layout.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use sikka_common::constants::{BOOTSTRAP_NODES, DEFAULT_PORT};
use sikka_common::error::{Error, Result};

/// How the node presents itself and where it keeps things.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Where redb files and the key live. Always `/data` in production.
    pub data_dir: PathBuf,
    /// Optional genesis document. When absent (or the path does not exist), the
    /// baked-in SIKKA genesis is used.
    pub genesis_path: PathBuf,
    /// ML-DSA-87 keystore. Always `/data/node_key.json` in production.
    pub key_path: PathBuf,
    /// Optional private key hex (32-byte seed or full 4896-byte secret). Wins
    /// over the keystore file.
    pub private_key: Option<String>,
    /// Address to bind the HTTP server to.
    pub listen: SocketAddr,
    /// The URL other nodes should use to reach this one.
    pub advertise: String,
    /// Peers to try when the peer book is empty.
    pub bootstrap: Vec<String>,
    /// SOCKS5 proxy for outbound requests, e.g. Tor at `127.0.0.1:9050`.
    pub socks5_proxy: Option<String>,
    /// Take part in consensus when bonded. Always `true` in production.
    pub validator: bool,
    /// Upper bound on transactions held in memory.
    pub mempool_capacity: usize,
    /// How often to check whether it is our turn to propose.
    pub propose_interval: Duration,
    /// How often to reconcile mempools with peers.
    pub gossip_interval: Duration,
    /// How often to re-announce and learn peers.
    pub discovery_interval: Duration,
    /// Per-request timeout for outbound peer calls.
    pub request_timeout: Duration,
    /// Seal a checkpoint after this long even if the pool is short of a full
    /// batch, so a quiet chain still makes progress. Zero disables it.
    pub max_checkpoint_delay: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        let data_dir = PathBuf::from("/data");
        Self {
            genesis_path: data_dir.join("genesis.json"),
            key_path: data_dir.join("node_key.json"),
            private_key: None,
            data_dir,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_PORT),
            advertise: format!("http://localhost:{DEFAULT_PORT}"),
            bootstrap: BOOTSTRAP_NODES.iter().map(|s| s.to_string()).collect(),
            socks5_proxy: None,
            validator: true,
            mempool_capacity: 50_000,
            propose_interval: Duration::from_millis(500),
            gossip_interval: Duration::from_secs(2),
            discovery_interval: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
            max_checkpoint_delay: Duration::from_secs(30),
        }
    }
}

impl NodeConfig {
    /// Read the remaining knobs from the environment.
    ///
    /// Data dir (`/data`), key path (`/data/node_key.json`), listen port
    /// ([`DEFAULT_PORT`]), and validator mode (`true`) are fixed. Tests may
    /// still override fields on a constructed [`NodeConfig`].
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        if let Some(path) = env("SIKKA_GENESIS") {
            config.genesis_path = PathBuf::from(path);
        }
        if let Some(key) = env("SIKKA_PRIVATE_KEY") {
            config.private_key = Some(key);
        }

        config.listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_PORT);

        config.advertise = match env("SIKKA_ADVERTISE") {
            Some(url) => normalize_endpoint(&url),
            None => {
                let host = env("HOSTNAME").unwrap_or_else(|| "localhost".to_string());
                format!("http://{host}:{DEFAULT_PORT}")
            }
        };

        if let Some(list) = env("SIKKA_BOOTSTRAP") {
            config.bootstrap = list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(normalize_endpoint)
                .collect();
        }
        if let Some(proxy) = env("SIKKA_TOR_PROXY").or_else(|| env("SIKKA_SOCKS5_PROXY")) {
            config.socks5_proxy = Some(proxy);
        }
        if let Some(capacity) = env("SIKKA_MEMPOOL_CAPACITY") {
            config.mempool_capacity = capacity.parse().map_err(|_| {
                Error::Other(format!("SIKKA_MEMPOOL_CAPACITY '{capacity}' invalid"))
            })?;
        }
        if let Some(secs) = env("SIKKA_MAX_CHECKPOINT_DELAY") {
            let secs: u64 = secs.parse().map_err(|_| {
                Error::Other(format!("SIKKA_MAX_CHECKPOINT_DELAY '{secs}' invalid"))
            })?;
            config.max_checkpoint_delay = Duration::from_secs(secs);
        }
        if let Some(ms) = env("SIKKA_PROPOSE_INTERVAL_MS") {
            let ms: u64 = ms
                .parse()
                .map_err(|_| Error::Other(format!("SIKKA_PROPOSE_INTERVAL_MS '{ms}' invalid")))?;
            config.propose_interval = Duration::from_millis(ms.max(50));
        }

        Ok(config)
    }

    pub fn state_path(&self) -> PathBuf {
        self.data_dir.join("state.redb")
    }

    pub fn checkpoints_path(&self) -> PathBuf {
        self.data_dir.join("checkpoints.redb")
    }
}

fn env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

/// Give a bare `host:port` a scheme so it can be used as a URL.
pub fn normalize_endpoint(endpoint: impl AsRef<str>) -> String {
    let endpoint = endpoint.as_ref().trim().trim_end_matches('/');
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("http://{endpoint}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_get_a_scheme_and_lose_trailing_slashes() {
        assert_eq!(normalize_endpoint("node1:8080"), "http://node1:8080");
        assert_eq!(
            normalize_endpoint("http://node1:8080/"),
            "http://node1:8080"
        );
        assert_eq!(normalize_endpoint("https://a.example"), "https://a.example");
        assert_eq!(normalize_endpoint("  node1:8080  "), "http://node1:8080");
    }

    #[test]
    fn defaults_are_container_shaped() {
        let config = NodeConfig::default();
        assert_eq!(config.data_dir, PathBuf::from("/data"));
        assert_eq!(config.key_path, PathBuf::from("/data/node_key.json"));
        assert_eq!(config.genesis_path, PathBuf::from("/data/genesis.json"));
        assert_eq!(config.state_path(), PathBuf::from("/data/state.redb"));
        assert_eq!(config.listen.port(), DEFAULT_PORT);
        assert!(
            config.listen.ip().is_unspecified(),
            "must bind all interfaces in a container"
        );
        assert!(config.validator);
        assert!(config.private_key.is_none());
    }
}
