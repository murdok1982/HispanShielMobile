use std::path::Path;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{error, info, warn};
use crate::policy::{PolicyEngine, Decision};
use std::sync::Arc;
use tokio::sync::RwLock;

/// A line-delimited JSON protocol message from a client.
/// Format: `{"uid": 1000, "dest": "example.com"}`
#[derive(serde::Deserialize, Debug)]
struct PolicyRequest {
    uid: u32,
    dest: String,
}

/// Response sent back to client.
#[derive(serde::Serialize, Debug)]
struct PolicyResponse {
    uid: u32,
    dest: String,
    decision: String,
}

pub struct SocketServer {
    socket_path: String,
    engine: Arc<RwLock<PolicyEngine>>,
}

impl SocketServer {
    pub fn new(socket_path: impl Into<String>, engine: Arc<RwLock<PolicyEngine>>) -> Self {
        Self {
            socket_path: socket_path.into(),
            engine,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let path = Path::new(&self.socket_path);

        // Remove stale socket if it exists
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(path)?;
        info!(socket = %self.socket_path, "NPD socket server listening");

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let engine = Arc::clone(&self.engine);
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, engine).await {
                            error!("Client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_client(
    stream: UnixStream,
    engine: Arc<RwLock<PolicyEngine>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<PolicyRequest>(&line) {
            Ok(req) => {
                let eng = engine.read().await;
                let decision = eng.evaluate(req.uid, &req.dest);
                info!(
                    uid = req.uid,
                    dest = %req.dest,
                    decision = %decision,
                    "Policy decision"
                );
                PolicyResponse {
                    uid: req.uid,
                    dest: req.dest,
                    decision: decision.to_string(),
                }
            }
            Err(e) => {
                warn!("Failed to parse request '{}': {}", line, e);
                PolicyResponse {
                    uid: 0,
                    dest: String::new(),
                    decision: Decision::Deny.to_string(),
                }
            }
        };

        let mut resp_json = serde_json::to_string(&response)?;
        resp_json.push('\n');
        writer.write_all(resp_json.as_bytes()).await?;
    }

    Ok(())
}
