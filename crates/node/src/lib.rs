//! A SIKKA node.
//!
//! One process, one port, one container: consensus participation, peer
//! federation and the wallet-facing JSON-RPC all live behind the same HTTP
//! server. The pieces are separated by what they do rather than by transport:
//!
//! - [`node::Node`] owns all state and every rule for changing it. It is
//!   entirely synchronous and holds no locks across await points.
//! - [`http`] translates HTTP into calls on `Node`.
//! - [`loops`] drives the same calls on timers.
//! - [`gossip`] and [`sync`] are the only places that talk to other nodes.

pub mod config;
pub mod gossip;
pub mod http;
pub mod loops;
pub mod node;
pub mod sync;

pub use config::{NodeConfig, TrustedCheckpoint};
pub use gossip::Gossip;
pub use node::{Finalized, Node};

use std::sync::Arc;

use sikka_common::error::{Error, Result};
use tracing::info;

/// A running node: the state, the relay, and the bound listener.
pub struct Running {
    pub node: Arc<Node>,
    pub gossip: Arc<Gossip>,
    pub local_addr: std::net::SocketAddr,
    listener: tokio::net::TcpListener,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Open the node and bind its port, without yet serving.
///
/// Binding before serving means a port conflict is reported at startup instead
/// of silently leaving the node unreachable, and lets tests learn the port the
/// OS picked.
pub async fn start(config: NodeConfig) -> Result<Running> {
    let node = Node::open(config)?;
    let (gossip, client) = Gossip::start(node.clone())?;

    let listener = tokio::net::TcpListener::bind(node.config().listen)
        .await
        .map_err(|e| Error::Network(format!("cannot bind {}: {e}", node.config().listen)))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| Error::Network(format!("cannot read the bound address: {e}")))?;

    let tasks = loops::spawn_all(node.clone(), gossip.clone(), client);

    info!(
        address = %node.address(),
        advertise = %node.config().advertise,
        listen = %local_addr,
        height = node.height(),
        validator = node.is_active_validator(),
        "node started"
    );
    Ok(Running {
        node,
        gossip,
        local_addr,
        listener,
        tasks,
    })
}

impl Running {
    /// Serve until `shutdown` resolves, then stop the background loops.
    pub async fn serve_until(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        let state = http::AppState {
            node: self.node.clone(),
            gossip: self.gossip.clone(),
        };
        let result = axum::serve(self.listener, http::router(state))
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(|e| Error::Network(format!("http server failed: {e}")));

        for task in self.tasks {
            task.abort();
        }
        info!(height = self.node.height(), "node stopped");
        result
    }
}
