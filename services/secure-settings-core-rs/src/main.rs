mod store;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/hispashield/settings.sock";
const DB_PATH: &str = "/data/hispashield/settings.json";

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum SettingsRequest {
    Get { key: String },
    Set { key: String, value: String },
    Delete { key: String },
    LockKey { key: String },
}

#[derive(Debug, Serialize)]
struct SettingsResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SettingsResponse {
    fn ok(value: Option<String>) -> Self {
        Self { success: true, value, error: None }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self { success: false, value: None, error: Some(msg.into()) }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("secure_settings_core=debug".parse().unwrap()),
        )
        .json()
        .init();

    info!("HispaShield Secure Settings Core starting");

    let store = store::SecureStore::load(DB_PATH)
        .context("Failed to load settings store")?;

    // Lock critical boot-time settings
    let mut store = store;
    let boot_keys = ["hispashield.avb_verified", "hispashield.dm_verity_mode"];
    for key in &boot_keys {
        // Set default if not present
        if store.get(key).is_err() {
            let _ = store.set(key, "strict".into());
        }
        let _ = store.lock_key(key);
    }

    let store = Arc::new(Mutex::new(store));

    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path).context("Failed to bind settings socket")?;
    info!(socket = SOCKET_PATH, "Settings daemon listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, store).await {
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
    store: Arc<Mutex<store::SecureStore>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response: SettingsResponse = match serde_json::from_str::<SettingsRequest>(&line) {
            Err(e) => {
                warn!("Parse error: {}", e);
                SettingsResponse::err(format!("parse error: {}", e))
            }
            Ok(req) => {
                let mut s = store.lock().await;
                match req {
                    SettingsRequest::Get { key } => match s.get(&key) {
                        Ok(v) => SettingsResponse::ok(Some(v)),
                        Err(e) => SettingsResponse::err(e.to_string()),
                    },
                    SettingsRequest::Set { key, value } => match s.set(&key, value) {
                        Ok(()) => SettingsResponse::ok(None),
                        Err(e) => SettingsResponse::err(e.to_string()),
                    },
                    SettingsRequest::Delete { key } => match s.delete(&key) {
                        Ok(()) => SettingsResponse::ok(None),
                        Err(e) => SettingsResponse::err(e.to_string()),
                    },
                    SettingsRequest::LockKey { key } => match s.lock_key(&key) {
                        Ok(()) => SettingsResponse::ok(None),
                        Err(e) => SettingsResponse::err(e.to_string()),
                    },
                }
            }
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }

    Ok(())
}
