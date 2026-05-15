mod firewall;
mod sni;

use anyhow::Result;
use firewall::FirewallManager;
use serde::{Deserialize, Serialize};
use sni::SniGuard;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Daemon state
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct KillSwitchState {
    active: bool,
    vpn_iface: Option<String>,
    vpn_endpoint: Option<String>,
    vpn_up: bool,
    leaked_queries: usize,
}

type SharedState = Arc<Mutex<KillSwitchState>>;

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request {
    Enable {
        vpn_iface: String,
        vpn_endpoint: String,
    },
    Disable,
    Status,
    VpnUp {
        iface: String,
    },
    VpnDown,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Ok { ok: bool, message: String },
    Status {
        active: bool,
        vpn_iface: Option<String>,
        vpn_up: bool,
        leaked_queries: usize,
    },
    Error { error: String },
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(stream: UnixStream, state: SharedState) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Err(e) => {
                warn!(err = %e, raw = %line, "Failed to parse request");
                Response::Error {
                    error: format!("parse error: {e}"),
                }
            }
            Ok(req) => process_request(req, Arc::clone(&state)).await,
        };

        let mut json = serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"error":"serialization error"}"#.to_string()
        });
        json.push('\n');

        if let Err(e) = writer.write_all(json.as_bytes()).await {
            error!(err = %e, "Failed to write response");
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Request dispatch
// ---------------------------------------------------------------------------

async fn process_request(req: Request, state: SharedState) -> Response {
    match req {
        Request::Enable {
            vpn_iface,
            vpn_endpoint,
        } => {
            let fw = FirewallManager::new(vpn_iface.clone(), vpn_endpoint.clone());
            match fw.block_all_except_vpn_endpoint().await {
                Ok(()) => {
                    let mut st = state.lock().await;
                    st.active = true;
                    st.vpn_iface = Some(vpn_iface.clone());
                    st.vpn_endpoint = Some(vpn_endpoint.clone());
                    info!(iface = %vpn_iface, endpoint = %vpn_endpoint, "Kill-switch enabled");
                    Response::Ok {
                        ok: true,
                        message: format!("Kill-switch enabled on {vpn_iface}"),
                    }
                }
                Err(e) => {
                    error!(err = %e, "Failed to enable kill-switch");
                    Response::Error {
                        error: format!("firewall error: {e}"),
                    }
                }
            }
        }

        Request::Disable => {
            let (iface, endpoint) = {
                let st = state.lock().await;
                (
                    st.vpn_iface.clone().unwrap_or_default(),
                    st.vpn_endpoint.clone().unwrap_or_default(),
                )
            };
            let fw = FirewallManager::new(iface, endpoint);
            match fw.restore_normal().await {
                Ok(()) => {
                    let mut st = state.lock().await;
                    st.active = false;
                    info!("Kill-switch disabled");
                    Response::Ok {
                        ok: true,
                        message: "Kill-switch disabled".to_string(),
                    }
                }
                Err(e) => {
                    error!(err = %e, "Failed to disable kill-switch");
                    Response::Error {
                        error: format!("firewall error: {e}"),
                    }
                }
            }
        }

        Request::Status => {
            let st = state.lock().await;
            Response::Status {
                active: st.active,
                vpn_iface: st.vpn_iface.clone(),
                vpn_up: st.vpn_up,
                leaked_queries: st.leaked_queries,
            }
        }

        Request::VpnUp { iface } => {
            info!(iface = %iface, "VPN up event received");
            let endpoint = {
                let st = state.lock().await;
                st.vpn_endpoint.clone().unwrap_or_default()
            };
            let fw = FirewallManager::new(iface.clone(), endpoint);
            if let Err(e) = fw.block_all_except_vpn_endpoint().await {
                warn!(err = %e, "Could not install VPN-up rules");
            }
            let mut st = state.lock().await;
            st.vpn_up = true;
            st.vpn_iface = Some(iface.clone());
            Response::Ok {
                ok: true,
                message: format!("VPN up on {iface}; kill-switch rules refreshed"),
            }
        }

        Request::VpnDown => {
            warn!("VPN down event — activating kill-switch immediately!");
            let (iface, endpoint) = {
                let st = state.lock().await;
                (
                    st.vpn_iface.clone().unwrap_or_default(),
                    st.vpn_endpoint.clone().unwrap_or_default(),
                )
            };
            let fw = FirewallManager::new(iface.clone(), endpoint);
            match fw.block_all_except_vpn_endpoint().await {
                Ok(()) => {
                    let mut st = state.lock().await;
                    st.vpn_up = false;
                    st.active = true;
                    Response::Ok {
                        ok: true,
                        message: "VPN down detected; internet blocked via kill-switch".to_string(),
                    }
                }
                Err(e) => {
                    error!(err = %e, "CRITICAL: kill-switch failed on VPN down!");
                    Response::Error {
                        error: format!("CRITICAL firewall error: {e}"),
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Background: route monitor & DNS-leak checker
// ---------------------------------------------------------------------------

async fn background_monitor(state: SharedState) {
    let guard = SniGuard::new();
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let (active, iface, endpoint) = {
            let st = state.lock().await;
            (
                st.active,
                st.vpn_iface.clone().unwrap_or_default(),
                st.vpn_endpoint.clone().unwrap_or_default(),
            )
        };

        let fw = FirewallManager::new(iface.clone(), endpoint.clone());

        // Check VPN route presence
        let vpn_present = fw.check_vpn_status().await;
        if active && !vpn_present {
            warn!("Route monitor: VPN route disappeared — triggering kill-switch");
            if let Err(e) = fw.block_all_except_vpn_endpoint().await {
                error!(err = %e, "Kill-switch failed in background monitor");
            }
            let mut st = state.lock().await;
            st.vpn_up = false;
        }

        // Check for DNS leaks
        let leaks = fw.detect_dns_leak().await;
        if !leaks.is_empty() {
            warn!(count = leaks.len(), leaks = ?leaks, "DNS leak candidates detected");
            let mut st = state.lock().await;
            st.leaked_queries += leaks.len();
        }

        // Check for SNI leaks
        let sni_leaks = guard.check_plaintext_sni().await;
        if !sni_leaks.is_empty() {
            warn!(
                count = sni_leaks.len(),
                "Plaintext SNI connections detected; ECH not in use"
            );
            for leak in &sni_leaks {
                warn!(dst = %leak.dst_addr, risk = %leak.risk, "SNI leak");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("vpn_killswitch=debug".parse().unwrap()),
        )
        .json()
        .init();

    let socket_path = "/run/hispashield/killswitch.sock";

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Remove stale socket
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = UnixListener::bind(socket_path)?;
    info!(socket = socket_path, "VPN kill-switch daemon listening");

    let state: SharedState = Arc::new(Mutex::new(KillSwitchState::default()));

    // Spawn background monitor
    tokio::spawn(background_monitor(Arc::clone(&state)));

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_connection(stream, state).await;
                });
            }
            Err(e) => {
                error!(err = %e, "Accept error");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_deserialize_enable() {
        let json = r#"{"action":"enable","vpn_iface":"tun0","vpn_endpoint":"1.2.3.4"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::Enable {
                vpn_iface,
                vpn_endpoint,
            } => {
                assert_eq!(vpn_iface, "tun0");
                assert_eq!(vpn_endpoint, "1.2.3.4");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_request_deserialize_disable() {
        let json = r#"{"action":"disable"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Disable));
    }

    #[test]
    fn test_request_deserialize_status() {
        let json = r#"{"action":"status"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Status));
    }

    #[test]
    fn test_request_deserialize_vpn_up() {
        let json = r#"{"action":"vpn_up","iface":"tun0"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::VpnUp { iface } if iface == "tun0"));
    }

    #[test]
    fn test_request_deserialize_vpn_down() {
        let json = r#"{"action":"vpn_down"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::VpnDown));
    }

    #[test]
    fn test_request_deserialize_unknown_action() {
        let json = r#"{"action":"unknown_action"}"#;
        let result: Result<Request, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_response_ok_serializes() {
        let resp = Response::Ok {
            ok: true,
            message: "hello".to_string(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("true"));
        assert!(s.contains("hello"));
    }

    #[test]
    fn test_response_status_serializes() {
        let resp = Response::Status {
            active: true,
            vpn_iface: Some("tun0".to_string()),
            vpn_up: true,
            leaked_queries: 3,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("tun0"));
        assert!(s.contains("3"));
    }

    #[test]
    fn test_response_error_serializes() {
        let resp = Response::Error {
            error: "something went wrong".to_string(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("something went wrong"));
    }

    #[tokio::test]
    async fn test_process_request_status_default() {
        let state: SharedState = Arc::new(Mutex::new(KillSwitchState::default()));
        let resp = process_request(Request::Status, Arc::clone(&state)).await;
        match resp {
            Response::Status {
                active,
                leaked_queries,
                ..
            } => {
                assert!(!active);
                assert_eq!(leaked_queries, 0);
            }
            _ => panic!("expected Status response"),
        }
    }
}
