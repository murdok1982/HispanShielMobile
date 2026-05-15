mod coordinator;

use anyhow::Context;
use coordinator::{CodecKind, IsolationConfig, ProcessManager};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/hispashield/mediaisolate.sock";
const CGROUP_BASE: &str = "/sys/fs/cgroup/hispashield_media";
const MONITOR_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum MediaRequest {
    SpawnCodec { kind: CodecKind },
    KillCodec { id: u64 },
    ListCodecs,
    CheckHealth { id: u64 },
}

#[derive(Debug, Serialize)]
struct MediaResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    codec_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    codec_ids: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("media_isolate_coordinator=debug".parse().unwrap()),
        )
        .json()
        .init();

    info!("HispaShield Media Isolate Coordinator starting");

    // Ensure cgroup base directory exists
    if let Err(e) = std::fs::create_dir_all(CGROUP_BASE) {
        warn!("Could not create cgroup base '{}': {} — continuing", CGROUP_BASE, e);
    }

    let manager = Arc::new(Mutex::new(ProcessManager::new(CGROUP_BASE)));

    // Spawn health-monitor task that checks all codec processes periodically
    let manager_monitor = Arc::clone(&manager);
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(MONITOR_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let ids: Vec<u64> = {
                let mgr = manager_monitor.lock().await;
                mgr.list_ids()
            };
            for id in ids {
                let mut mgr = manager_monitor.lock().await;
                match mgr.check_and_restart(id) {
                    Ok(None) => {} // still alive
                    Ok(Some(new_id)) => {
                        info!(old_id = id, new_id, "Codec process restarted by monitor");
                    }
                    Err(e) => {
                        error!(id, error = %e, "Codec process permanently failed");
                    }
                }
            }
        }
    });

    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener =
        UnixListener::bind(path).context("Failed to bind media isolate socket")?;
    info!(socket = SOCKET_PATH, "Media isolate coordinator listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let manager = Arc::clone(&manager);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, manager).await {
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
    manager: Arc<Mutex<ProcessManager>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response: MediaResponse = match serde_json::from_str::<MediaRequest>(&line) {
            Err(e) => {
                warn!("Parse error: {}", e);
                MediaResponse { success: false, codec_id: None, codec_ids: None, error: Some(e.to_string()) }
            }
            Ok(req) => {
                let mut mgr = manager.lock().await;
                match req {
                    MediaRequest::SpawnCodec { kind } => {
                        let config = IsolationConfig::default_for_kind(kind);
                        match mgr.spawn_codec(config) {
                            Ok(id) => MediaResponse { success: true, codec_id: Some(id), codec_ids: None, error: None },
                            Err(e) => MediaResponse { success: false, codec_id: None, codec_ids: None, error: Some(e.to_string()) },
                        }
                    }
                    MediaRequest::KillCodec { id } => {
                        let killed = mgr.kill_codec(id);
                        MediaResponse {
                            success: killed,
                            codec_id: Some(id),
                            codec_ids: None,
                            error: if killed { None } else { Some("codec not found".into()) },
                        }
                    }
                    MediaRequest::ListCodecs => {
                        MediaResponse { success: true, codec_id: None, codec_ids: Some(mgr.list_ids()), error: None }
                    }
                    MediaRequest::CheckHealth { id } => {
                        match mgr.check_and_restart(id) {
                            Ok(None) => MediaResponse { success: true, codec_id: Some(id), codec_ids: None, error: None },
                            Ok(Some(new_id)) => MediaResponse { success: true, codec_id: Some(new_id), codec_ids: None, error: Some("restarted".into()) },
                            Err(e) => MediaResponse { success: false, codec_id: Some(id), codec_ids: None, error: Some(e.to_string()) },
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
