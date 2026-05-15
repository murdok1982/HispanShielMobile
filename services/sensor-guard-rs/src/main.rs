mod guard;

use anyhow::Context;
use guard::{SensorGuard, SensorKind, SensorPermissions};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/hispashield/sensorguard.sock";
const PERMISSIONS_FILE: &str = "/data/hispashield/sensor_permissions.json";
const PURGE_INTERVAL_SECS: u64 = 120;

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum ClientRequest {
    RequestAccess { uid: u32, sensor: SensorKind },
    ValidateToken { token_id: u64 },
    RevokeToken { token_id: u64 },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct ClientResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_secs: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sensor_guard=debug".parse().unwrap()),
        )
        .json()
        .init();

    info!("HispaShield Sensor Guard starting");

    let mut guard = SensorGuard::new();

    // Load permissions from file if present
    match std::fs::read_to_string(PERMISSIONS_FILE) {
        Ok(content) => match serde_json::from_str::<Vec<SensorPermissions>>(&content) {
            Ok(perms) => guard.load_permissions(perms),
            Err(e) => warn!("Failed to parse permissions file: {}", e),
        },
        Err(e) => warn!("Could not read permissions file '{}': {}", PERMISSIONS_FILE, e),
    }

    let guard = Arc::new(Mutex::new(guard));

    // Spawn periodic token GC
    let guard_gc = Arc::clone(&guard);
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(PURGE_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let mut g = guard_gc.lock().await;
            g.purge_expired();
        }
    });

    // Set up Unix domain socket
    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path).context("Failed to bind sensor-guard socket")?;
    info!(socket = SOCKET_PATH, "Sensor guard listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let guard_conn = Arc::clone(&guard);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, guard_conn).await {
                        error!("Client error: {}", e);
                    }
                });
            }
            Err(e) => error!("Accept error: {}", e),
        }
    }
}

async fn handle_client(
    stream: UnixStream,
    guard: Arc<Mutex<SensorGuard>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response: ClientResponse = match serde_json::from_str::<ClientRequest>(&line) {
            Err(e) => {
                warn!("Malformed request '{}': {}", line, e);
                ClientResponse {
                    success: false,
                    token_id: None,
                    error: Some(format!("parse error: {}", e)),
                    remaining_secs: None,
                }
            }
            Ok(req) => {
                let mut g = guard.lock().await;
                match req {
                    ClientRequest::RequestAccess { uid, sensor } => {
                        match g.request_access(uid, sensor) {
                            Ok(token) => ClientResponse {
                                success: true,
                                token_id: Some(token.token_id),
                                error: None,
                                remaining_secs: Some(token.remaining().as_secs()),
                            },
                            Err(e) => ClientResponse {
                                success: false,
                                token_id: None,
                                error: Some(e.to_string()),
                                remaining_secs: None,
                            },
                        }
                    }
                    ClientRequest::ValidateToken { token_id } => match g.validate_token(token_id) {
                        Ok(token) => ClientResponse {
                            success: true,
                            token_id: Some(token_id),
                            error: None,
                            remaining_secs: Some(token.remaining().as_secs()),
                        },
                        Err(e) => ClientResponse {
                            success: false,
                            token_id: Some(token_id),
                            error: Some(e.to_string()),
                            remaining_secs: None,
                        },
                    },
                    ClientRequest::RevokeToken { token_id } => {
                        let revoked = g.revoke_token(token_id);
                        ClientResponse {
                            success: revoked,
                            token_id: Some(token_id),
                            error: if revoked { None } else { Some("unknown token".into()) },
                            remaining_secs: None,
                        }
                    }
                }
            }
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }

    Ok(())
}
