//! Tor Transparent Proxy daemon — HispaShield Mobile
//!
//! Listens on a Unix-domain socket, manages the Tor process lifecycle and
//! iptables TPROXY rules, and exposes a newline-delimited JSON control API.

mod iptables;
mod tor_manager;
mod torrc;

use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use iptables::TproxyRules;
use tor_manager::{TorConfig, TorManager};

// ─── Configuration ─────────────────────────────────────────────────────────

const SOCKET_PATH: &str = "/run/hispashield/tor-proxy.sock";
/// UID we assume the Tor process runs as on HispaShield (dedicated system user).
const TOR_PROCESS_UID: u32 = 10101;
/// Simulated Tor version string (replace with runtime detection).
const TOR_VERSION: &str = "0.4.8.12";

// ─── Shared daemon state ──────────────────────────────────────────────────

struct DaemonState {
    tor_manager: TorManager,
    tproxy_rules: TproxyRules,
    bypass_uids: Vec<u32>,
    preferred_exit_country: Option<String>,
}

impl DaemonState {
    fn new(config: TorConfig) -> Self {
        let bypass_uids = config.bypass_uids.clone();
        let tproxy = TproxyRules {
            tor_uid: TOR_PROCESS_UID,
            transparent_port: config.transparent_port,
            dns_port: config.dns_port,
            bypass_uids: bypass_uids.clone(),
        };
        Self {
            tor_manager: TorManager::new(config),
            tproxy_rules: tproxy,
            bypass_uids,
            preferred_exit_country: None,
        }
    }
}

// ─── JSON protocol ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Request {
    action: String,
    /// For add_bypass / remove_bypass.
    uid: Option<u32>,
    /// For set_exit_country.
    country: Option<String>,
}

#[derive(Debug, Serialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tor_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    circuit_established: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bypass_uids: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            active: None,
            tor_version: None,
            circuit_established: None,
            exit_country: None,
            bypass_uids: None,
            message: Some(message.into()),
            error: None,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            active: None,
            tor_version: None,
            circuit_established: None,
            exit_country: None,
            bypass_uids: None,
            message: None,
            error: Some(msg.into()),
        }
    }
}

// ─── Request dispatch ─────────────────────────────────────────────────────

async fn handle_request(req: Request, state: Arc<Mutex<DaemonState>>) -> Response {
    match req.action.as_str() {
        // ── enable ────────────────────────────────────────────────────────────
        "enable" => {
            let mut st = state.lock().await;
            if st.tor_manager.is_running() {
                return Response::err("Tor is already active");
            }
            if let Err(e) = st.tor_manager.start().await {
                return Response::err(format!("Failed to start Tor: {e}"));
            }
            if let Err(e) = st.tproxy_rules.apply().await {
                // Roll back Tor if iptables fails
                let _ = st.tor_manager.stop().await;
                return Response::err(format!("Failed to apply iptables rules: {e}"));
            }
            Response::ok("Tor enabled — all traffic now routed through Tor")
        }

        // ── disable ───────────────────────────────────────────────────────────
        "disable" => {
            let mut st = state.lock().await;
            // Remove iptables rules first to restore direct routing
            if let Err(e) = st.tproxy_rules.remove().await {
                warn!("Failed to remove iptables rules: {e}");
            }
            if let Err(e) = st.tor_manager.stop().await {
                return Response::err(format!("Failed to stop Tor: {e}"));
            }
            Response::ok("Tor disabled — direct routing restored")
        }

        // ── status ────────────────────────────────────────────────────────────
        "status" => {
            let st = state.lock().await;
            let active = st.tor_manager.is_running();
            let circuit = st.tor_manager.circuit_established;
            let exit = st.tor_manager.exit_country.clone()
                .or_else(|| st.preferred_exit_country.clone());
            Response {
                active: Some(active),
                tor_version: Some(TOR_VERSION.to_string()),
                circuit_established: Some(circuit),
                exit_country: exit,
                bypass_uids: Some(st.bypass_uids.clone()),
                message: None,
                error: None,
            }
        }

        // ── new_circuit ───────────────────────────────────────────────────────
        "new_circuit" => {
            let st = state.lock().await;
            match st.tor_manager.new_circuit().await {
                Ok(info) => Response::ok(format!("New circuit established: {info}")),
                Err(e) => Response::err(format!("new_circuit failed: {e}")),
            }
        }

        // ── add_bypass ────────────────────────────────────────────────────────
        "add_bypass" => {
            let uid = match req.uid {
                Some(u) => u,
                None => return Response::err("Missing field: uid"),
            };
            let mut st = state.lock().await;
            if st.bypass_uids.contains(&uid) {
                return Response::ok(format!("UID {uid} already in bypass list"));
            }
            if st.tor_manager.is_running() {
                if let Err(e) = st.tproxy_rules.add_bypass_uid(uid).await {
                    return Response::err(format!("iptables add_bypass failed: {e}"));
                }
            }
            st.bypass_uids.push(uid);
            st.tproxy_rules.bypass_uids = st.bypass_uids.clone();
            Response::ok(format!("UID {uid} added to bypass list"))
        }

        // ── remove_bypass ─────────────────────────────────────────────────────
        "remove_bypass" => {
            let uid = match req.uid {
                Some(u) => u,
                None => return Response::err("Missing field: uid"),
            };
            let mut st = state.lock().await;
            if !st.bypass_uids.contains(&uid) {
                return Response::ok(format!("UID {uid} not in bypass list"));
            }
            if st.tor_manager.is_running() {
                if let Err(e) = st.tproxy_rules.remove_bypass_uid(uid).await {
                    warn!("iptables remove_bypass for UID {uid}: {e}");
                }
            }
            st.bypass_uids.retain(|&u| u != uid);
            st.tproxy_rules.bypass_uids = st.bypass_uids.clone();
            Response::ok(format!("UID {uid} removed from bypass list"))
        }

        // ── set_exit_country ──────────────────────────────────────────────────
        "set_exit_country" => {
            let country = match req.country {
                Some(c) => c.to_uppercase(),
                None => return Response::err("Missing field: country"),
            };
            // Validate: 2-letter ISO 3166-1 alpha-2
            if country.len() != 2 || !country.chars().all(|c| c.is_ascii_alphabetic()) {
                return Response::err(format!("Invalid country code: {country}"));
            }
            let exit_node = format!("{{{country}}}");
            let mut st = state.lock().await;
            st.preferred_exit_country = Some(country.clone());
            // Update config for next Tor start / NEWNYM
            st.tor_manager.config.exit_nodes = vec![exit_node.clone()];

            if st.tor_manager.is_running() {
                // Request a new circuit with the updated exit preference
                // (Tor will pick a new exit on the next NEWNYM)
                if let Err(e) = st.tor_manager.new_circuit().await {
                    warn!("Could not immediately change circuit after exit change: {e}");
                }
            }
            Response::ok(format!("Exit country set to {country}; new circuit requested"))
        }

        other => Response::err(format!("Unknown action: {other}")),
    }
}

// ─── Connection handler ────────────────────────────────────────────────────

async fn handle_connection(stream: tokio::net::UnixStream, state: Arc<Mutex<DaemonState>>) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                info!(action = %req.action, "Received request");
                handle_request(req, Arc::clone(&state)).await
            }
            Err(e) => {
                warn!("JSON parse error: {e}");
                Response::err(format!("JSON parse error: {e}"))
            }
        };

        let mut resp_json = match serde_json::to_string(&response) {
            Ok(j) => j,
            Err(e) => {
                error!("Serialisation error: {e}");
                format!("{{\"error\":\"serialisation error: {e}\"}}"),
            }
        };
        resp_json.push('\n');

        if let Err(e) = writer.write_all(resp_json.as_bytes()).await {
            warn!("Write error: {e}");
            break;
        }
    }
}

// ─── Background circuit monitor ───────────────────────────────────────────

/// Polls Tor every 30 seconds and updates `circuit_established` + `exit_country`.
async fn circuit_monitor(state: Arc<Mutex<DaemonState>>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
    loop {
        interval.tick().await;
        let running = {
            let st = state.lock().await;
            st.tor_manager.is_running()
        };
        if !running {
            continue;
        }
        let result = {
            let st = state.lock().await;
            st.tor_manager.get_exit_info().await
        };
        match result {
            Ok((fp, country)) => {
                let mut st = state.lock().await;
                st.tor_manager.circuit_established = true;
                st.tor_manager.exit_country = Some(country.clone());
                info!(fingerprint = %fp, exit_country = %country, "Circuit status updated");
            }
            Err(e) => {
                warn!("Circuit monitor error: {e}");
                let mut st = state.lock().await;
                st.tor_manager.circuit_established = false;
            }
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    info!("tor-proxy daemon starting");

    if let Some(parent) = std::path::Path::new(SOCKET_PATH).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating socket directory: {:?}", parent))?;
    }

    // Remove stale socket from previous run
    let _ = std::fs::remove_file(SOCKET_PATH);

    let config = TorConfig::default();
    let state = Arc::new(Mutex::new(DaemonState::new(config)));

    // Spawn background circuit monitor
    tokio::spawn(circuit_monitor(Arc::clone(&state)));

    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("Binding socket: {SOCKET_PATH}"))?;

    info!(socket = SOCKET_PATH, "Listening for connections");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_connection(stream, state).await;
                });
            }
            Err(e) => {
                error!("Accept error: {e}");
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> Arc<Mutex<DaemonState>> {
        Arc::new(Mutex::new(DaemonState::new(TorConfig::default())))
    }

    #[tokio::test]
    async fn status_when_inactive() {
        let state = make_state();
        let req = Request {
            action: "status".to_string(),
            uid: None,
            country: None,
        };
        let resp = handle_request(req, state).await;
        assert_eq!(resp.active, Some(false));
        assert_eq!(resp.circuit_established, Some(false));
        assert!(resp.error.is_none());
        assert_eq!(resp.tor_version.as_deref(), Some(TOR_VERSION));
    }

    #[tokio::test]
    async fn disable_when_not_running_returns_error() {
        let state = make_state();
        let req = Request {
            action: "disable".to_string(),
            uid: None,
            country: None,
        };
        let resp = handle_request(req, state).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn add_and_remove_bypass() {
        let state = make_state();

        let add = Request {
            action: "add_bypass".to_string(),
            uid: Some(1234),
            country: None,
        };
        let resp = handle_request(add, Arc::clone(&state)).await;
        assert!(resp.error.is_none(), "add_bypass error: {:?}", resp.error);
        assert!(resp.message.as_ref().unwrap().contains("1234"));

        // Verify state contains the UID
        {
            let st = state.lock().await;
            assert!(st.bypass_uids.contains(&1234));
        }

        let remove = Request {
            action: "remove_bypass".to_string(),
            uid: Some(1234),
            country: None,
        };
        let resp2 = handle_request(remove, Arc::clone(&state)).await;
        assert!(resp2.error.is_none());

        {
            let st = state.lock().await;
            assert!(!st.bypass_uids.contains(&1234));
        }
    }

    #[tokio::test]
    async fn add_bypass_missing_uid_fails() {
        let state = make_state();
        let req = Request {
            action: "add_bypass".to_string(),
            uid: None,
            country: None,
        };
        let resp = handle_request(req, state).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn set_exit_country_valid() {
        let state = make_state();
        let req = Request {
            action: "set_exit_country".to_string(),
            uid: None,
            country: Some("DE".to_string()),
        };
        let resp = handle_request(req, Arc::clone(&state)).await;
        assert!(resp.error.is_none(), "error: {:?}", resp.error);
        let st = state.lock().await;
        assert_eq!(st.preferred_exit_country.as_deref(), Some("DE"));
        assert_eq!(st.tor_manager.config.exit_nodes, vec!["{DE}"]);
    }

    #[tokio::test]
    async fn set_exit_country_invalid_code() {
        let state = make_state();
        let req = Request {
            action: "set_exit_country".to_string(),
            uid: None,
            country: Some("GERMANY".to_string()),
        };
        let resp = handle_request(req, state).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn set_exit_country_missing_field() {
        let state = make_state();
        let req = Request {
            action: "set_exit_country".to_string(),
            uid: None,
            country: None,
        };
        let resp = handle_request(req, state).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn unknown_action() {
        let state = make_state();
        let req = Request {
            action: "hack_the_planet".to_string(),
            uid: None,
            country: None,
        };
        let resp = handle_request(req, state).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn new_circuit_when_tor_not_running() {
        let state = make_state();
        let req = Request {
            action: "new_circuit".to_string(),
            uid: None,
            country: None,
        };
        let resp = handle_request(req, state).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn bypass_uids_shown_in_status() {
        let state = make_state();

        for uid in &[911u32, 112u32] {
            let add = Request {
                action: "add_bypass".to_string(),
                uid: Some(*uid),
                country: None,
            };
            handle_request(add, Arc::clone(&state)).await;
        }

        let req = Request {
            action: "status".to_string(),
            uid: None,
            country: None,
        };
        let resp = handle_request(req, state).await;
        let uids = resp.bypass_uids.unwrap();
        assert!(uids.contains(&911));
        assert!(uids.contains(&112));
    }
}
