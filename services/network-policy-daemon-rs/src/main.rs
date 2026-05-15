mod policy;
mod socket;

use anyhow::Context;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

const SOCKET_PATH: &str = "/run/hispashield/npd.sock";
const POLICY_FILE: &str = "/data/hispashield/npd_rules.json";
const RELOAD_INTERVAL_SECS: u64 = 60;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("network_policy_daemon=debug".parse().unwrap()),
        )
        .json()
        .init();

    info!("HispaShield Network Policy Daemon starting");

    // Load initial policy — if file missing, start with empty (deny-all by default)
    let engine = match policy::PolicyEngine::load_from_file(POLICY_FILE) {
        Ok(e) => {
            info!(rules = e.rule_count(), "Policy loaded successfully");
            e
        }
        Err(err) => {
            error!(%err, "Could not load policy file, starting with empty (default-deny) policy");
            policy::PolicyEngine::new()
        }
    };

    let engine = Arc::new(RwLock::new(engine));

    // Spawn background task that reloads policy periodically
    let engine_reload = Arc::clone(&engine);
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(RELOAD_INTERVAL_SECS));
        loop {
            interval.tick().await;
            match policy::PolicyEngine::load_from_file(POLICY_FILE) {
                Ok(new_engine) => {
                    let count = new_engine.rule_count();
                    let mut guard = engine_reload.write().await;
                    *guard = new_engine;
                    info!(rules = count, "Policy reloaded");
                }
                Err(err) => {
                    error!(%err, "Policy reload failed, keeping existing rules");
                }
            }
        }
    });

    // Run the Unix socket server (blocks until error)
    let server = socket::SocketServer::new(SOCKET_PATH, Arc::clone(&engine));
    server.run().await.context("Socket server terminated")?;

    Ok(())
}
