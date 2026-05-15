mod switch;

use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
    time,
};
use tracing::{error, info, warn};

use switch::{DeadmanConfig, DeadmanSwitch, SwitchState};

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request {
    /// Refresh the heartbeat timer.
    Heartbeat { token: String },
    /// Query current switch state.
    Status,
    /// Reconfigure the switch parameters.
    Configure {
        interval_hours: Option<f64>,
        warning_minutes: Option<f64>,
        token_hash: Option<String>,
        keys_path: Option<String>,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Heartbeat {
        result: &'static str,
        next_deadline: String,
    },
    Status {
        state: SwitchState,
        seconds_remaining: u64,
    },
    Configure {
        result: &'static str,
    },
    Error {
        error: String,
    },
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct DaemonState {
    switch: DeadmanSwitch,
}

// ---------------------------------------------------------------------------
// Background tick task
// ---------------------------------------------------------------------------

async fn background_tick(state: Arc<Mutex<DaemonState>>) {
    let mut interval = time::interval(time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let mut st = state.lock().await;
        let new_state = st.switch.tick();
        if new_state == SwitchState::WipePending {
            warn!("deadman switch reached WipePending – executing wipe");
            let sw = &st.switch;
            if let Err(e) = sw.execute_wipe().await {
                error!("wipe failed: {e}");
            }
            // execute_wipe exits the process on success; if we get here it failed.
        }
    }
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

        let response = match serde_json::from_str::<Request>(&line) {
            Err(e) => Response::Error {
                error: format!("parse error: {e}"),
            },
            Ok(Request::Heartbeat { token }) => {
                let mut st = state.lock().await;
                let accepted = st.switch.heartbeat(&token);
                if accepted {
                    let deadline: DateTime<Utc> = Utc::now()
                        + ChronoDuration::seconds(
                            st.switch.config().interval_seconds as i64,
                        );
                    Response::Heartbeat {
                        result: "ok",
                        next_deadline: deadline.to_rfc3339(),
                    }
                } else {
                    Response::Error {
                        error: "invalid token".to_string(),
                    }
                }
            }
            Ok(Request::Status) => {
                let st = state.lock().await;
                Response::Status {
                    state: st.switch.state().clone(),
                    seconds_remaining: st.switch.seconds_remaining(),
                }
            }
            Ok(Request::Configure {
                interval_hours,
                warning_minutes,
                token_hash,
                keys_path,
            }) => {
                let mut st = state.lock().await;
                let old_cfg = st.switch.config().clone();
                let new_cfg = DeadmanConfig {
                    interval_seconds: interval_hours
                        .map(|h| (h * 3600.0) as u64)
                        .unwrap_or(old_cfg.interval_seconds),
                    warning_seconds: warning_minutes
                        .map(|m| (m * 60.0) as u64)
                        .unwrap_or(old_cfg.warning_seconds),
                    token_hash: token_hash.unwrap_or(old_cfg.token_hash),
                    keys_path: keys_path.unwrap_or(old_cfg.keys_path),
                };
                st.switch.reconfigure(new_cfg);
                info!("switch reconfigured via socket");
                Response::Configure { result: "ok" }
            }
        };

        let mut bytes = serde_json::to_vec(&response).unwrap_or_default();
        bytes.push(b'\n');
        if let Err(e) = writer.write_all(&bytes).await {
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

    // Load config from env or use sane defaults.
    let interval_hours: f64 = std::env::var("DEADMAN_INTERVAL_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24.0);
    let warning_minutes: f64 = std::env::var("DEADMAN_WARNING_MINUTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30.0);
    let token_hash = std::env::var("DEADMAN_TOKEN_HASH").unwrap_or_default();
    let keys_path = std::env::var("DEADMAN_KEYS_PATH")
        .unwrap_or_else(|_| "/data/hispashield/keys".to_string());

    let config = DeadmanConfig {
        interval_seconds: (interval_hours * 3600.0) as u64,
        warning_seconds: (warning_minutes * 60.0) as u64,
        token_hash,
        keys_path,
    };

    let sw = DeadmanSwitch::new(config);
    let state = Arc::new(Mutex::new(DaemonState { switch: sw }));

    // Start background tick task.
    let state_tick = Arc::clone(&state);
    tokio::spawn(background_tick(state_tick));

    let sock_path = "/run/hispashield/deadman.sock";
    let _ = std::fs::remove_file(sock_path);
    if let Some(parent) = std::path::Path::new(sock_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket dir {parent:?}"))?;
    }

    let listener = UnixListener::bind(sock_path)
        .with_context(|| format!("binding Unix socket {sock_path}"))?;

    info!("deadman-switch daemon listening on {sock_path}");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state_c = Arc::clone(&state);
                tokio::spawn(handle_connection(stream, state_c));
            }
            Err(e) => error!("accept error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sha256_hex(s: &str) -> String {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        hex::encode(h.finalize())
    }

    fn make_state() -> Arc<Mutex<DaemonState>> {
        let cfg = DeadmanConfig {
            interval_seconds: 3600,
            warning_seconds: 300,
            token_hash: sha256_hex("tok"),
            keys_path: "/tmp/test_keys".to_string(),
        };
        Arc::new(Mutex::new(DaemonState {
            switch: DeadmanSwitch::new(cfg),
        }))
    }

    #[tokio::test]
    async fn test_status_response_structure() {
        let state = make_state();
        let st = state.lock().await;
        let remaining = st.switch.seconds_remaining();
        let resp = Response::Status {
            state: st.switch.state().clone(),
            seconds_remaining: remaining,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("seconds_remaining"));
        assert!(json.contains("active"));
    }

    #[tokio::test]
    async fn test_heartbeat_accepted() {
        let state = make_state();
        let mut st = state.lock().await;
        assert!(st.switch.heartbeat(&sha256_hex("tok")));
    }

    #[tokio::test]
    async fn test_heartbeat_rejected() {
        let state = make_state();
        let mut st = state.lock().await;
        assert!(!st.switch.heartbeat(&sha256_hex("bad")));
    }

    #[test]
    fn test_request_parse_heartbeat() {
        let json = r#"{"action":"heartbeat","token":"abc123"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::Heartbeat { token } => assert_eq!(token, "abc123"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_request_parse_status() {
        let json = r#"{"action":"status"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Status));
    }

    #[test]
    fn test_request_parse_configure() {
        let json = r#"{"action":"configure","interval_hours":48,"warning_minutes":60}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::Configure {
                interval_hours,
                warning_minutes,
                ..
            } => {
                assert_eq!(interval_hours, Some(48.0));
                assert_eq!(warning_minutes, Some(60.0));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_switch_state_serializes() {
        let s = SwitchState::WipePending;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"wipe_pending\"");
    }
}
