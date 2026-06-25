//! The node binary.
//!
//! Configuration comes from the environment (see [`sikka_node::NodeConfig`]).
//! `sikka-node --prepare-tor` writes deterministic HS keys + torrc for the
//! Docker entrypoint; otherwise the node serves forever.

use tracing_subscriber::EnvFilter;

use sikka_node::{prepare_tor, NodeConfig};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();

    let prepare_only = std::env::args().any(|a| a == "--prepare-tor");

    let config = match NodeConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = %e, "invalid configuration");
            return std::process::ExitCode::from(2);
        }
    };

    if prepare_only {
        return match prepare_tor(&config) {
            Ok(advertise) => {
                tracing::info!(%advertise, "tor hidden service prepared");
                println!("{advertise}");
                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                tracing::error!(error = %e, "tor prepare failed");
                std::process::ExitCode::FAILURE
            }
        };
    }

    let running = match sikka_node::start(config).await {
        Ok(running) => running,
        Err(e) => {
            tracing::error!(error = %e, "node failed to start");
            return std::process::ExitCode::FAILURE;
        }
    };

    match running.serve_until(shutdown_signal()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "node stopped with an error");
            std::process::ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("SIKKA_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info,sikka_node=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}

/// Stop on Ctrl-C or SIGTERM, so `docker stop` is a clean shutdown rather than a
/// ten-second wait followed by SIGKILL.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => tracing::warn!(error = %e, "cannot listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl-C; shutting down"),
        _ = terminate => tracing::info!("received SIGTERM; shutting down"),
    }
}
