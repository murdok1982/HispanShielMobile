mod duress;

use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
use tracing::{error, info, warn};

use duress::{DuressConfig, DuressEngine, PinResult};

// ---------------------------------------------------------------------------
// Socket protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request {
    VerifyPin { pin_hash: String },
}

/// Response is deliberately identical for Normal and Duress so the attacker
/// cannot distinguish them by observing the wire protocol.
#[derive(Debug, Serialize)]
struct VerifyPinResponse {
    result: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Shared daemon state
// ---------------------------------------------------------------------------

struct DaemonState {
    engine: DuressEngine,
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(stream: UnixStream, state: Arc<Mutex<DaemonState>>) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response_bytes = match serde_json::from_str::<Request>(&line) {
            Err(e) => {
                let resp = ErrorResponse {
                    error: format!("parse error: {e}"),
                };
                serde_json::to_vec(&resp).unwrap_or_default()
            }
            Ok(Request::VerifyPin { pin_hash }) => {
                let st = state.lock().await;
                let result = st.engine.verify_pin(&pin_hash);

                // Spawn duress tasks BEFORE releasing the lock so we are
                // certain the engine config is still alive.
                if result == PinResult::Duress {
                    // Clone engine config to move into background task.
                    // NOTE: we intentionally do NOT log the duress event locally.
                    let engine = DuressEngine::new(st.engine.config().clone());
                    drop(st); // release lock early
                    tokio::spawn(async move {
                        if let Err(e) = engine.trigger_duress().await {
                            // Suppress error output to avoid leaving traces.
                            let _ = e;
                        }
                    });
                } else {
                    drop(st);
                }

                // Always respond "normal" – indistinguishable response.
                let resp = VerifyPinResponse { result: "normal" };
                serde_json::to_vec(&resp).unwrap_or_default()
            }
        };

        let mut out = response_bytes;
        out.push(b'\n');
        if let Err(e) = writer.write_all(&out).await {
            warn!("write error: {e}");
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::var("DURESS_CONFIG")
        .unwrap_or_else(|_| "/data/hispashield/duress_config.json".to_string());

    let config = DuressConfig::load(&config_path)
        .await
        .with_context(|| "loading duress config")?;

    let engine = DuressEngine::new(config);
    let state = Arc::new(Mutex::new(DaemonState { engine }));

    let sock_path = "/run/hispashield/duress.sock";
    // Remove stale socket if present.
    let _ = std::fs::remove_file(sock_path);
    // Ensure parent directory exists.
    if let Some(parent) = std::path::Path::new(sock_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket directory {parent:?}"))?;
    }

    let listener = UnixListener::bind(sock_path)
        .with_context(|| format!("binding Unix socket at {sock_path}"))?;

    info!("duress-pin-daemon listening on {sock_path}");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state_clone = Arc::clone(&state);
                tokio::spawn(handle_connection(stream, state_clone));
            }
            Err(e) => {
                error!("accept error: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use duress::DuressConfig;
    use sha2::{Digest, Sha256};

    fn sha256_hex(s: &str) -> String {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        hex::encode(h.finalize())
    }

    fn make_state() -> Arc<Mutex<DaemonState>> {
        let cfg = DuressConfig {
            normal_pin_hash: sha256_hex("1234"),
            duress_pin_hash: sha256_hex("9999"),
            beacon_addr: "127.0.0.1:19999".to_string(),
            beacon_key: hex::encode(b"testkey"),
            keys_path: "/tmp/hispashield_test_keys".to_string(),
            decoy_data_path: "/tmp/hispashield_decoy".to_string(),
        };
        Arc::new(Mutex::new(DaemonState {
            engine: DuressEngine::new(cfg),
        }))
    }

    #[tokio::test]
    async fn test_normal_pin_returns_normal() {
        let state = make_state();
        let st = state.lock().await;
        let result = st.engine.verify_pin(&sha256_hex("1234"));
        assert_eq!(result, PinResult::Normal);
    }

    #[tokio::test]
    async fn test_duress_pin_returns_duress() {
        let state = make_state();
        let st = state.lock().await;
        let result = st.engine.verify_pin(&sha256_hex("9999"));
        assert_eq!(result, PinResult::Duress);
    }

    #[tokio::test]
    async fn test_invalid_pin_returns_invalid() {
        let state = make_state();
        let st = state.lock().await;
        let result = st.engine.verify_pin(&sha256_hex("wrong"));
        assert_eq!(result, PinResult::Invalid);
    }

    #[test]
    fn test_request_parse_verify_pin() {
        let json = r#"{"action":"verify_pin","pin_hash":"aabbcc"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::VerifyPin { pin_hash } => assert_eq!(pin_hash, "aabbcc"),
        }
    }

    #[test]
    fn test_response_is_always_normal_string() {
        let resp = VerifyPinResponse { result: "normal" };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"normal\""));
    }
}
