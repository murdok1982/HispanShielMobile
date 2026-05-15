mod at_filter;

use anyhow::Context;
use at_filter::{ATCommand, CommandFilter, FilterVerdict};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/hispashield/basebandproxy.sock";

/// Raw AT command from an app (via the HAL shim)
#[derive(Debug, Deserialize)]
struct AtRequest {
    /// The raw AT command string
    command: String,
    /// UID of the requesting process
    uid: u32,
}

/// Response from the proxy
#[derive(Debug, Serialize)]
struct AtResponse {
    allowed: bool,
    /// If allowed, the (possibly sanitized) command to forward to modem
    #[serde(skip_serializing_if = "Option::is_none")]
    forwarded_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("baseband_proxy_hal=debug".parse().unwrap()),
        )
        .json()
        .init();

    info!("HispaShield Baseband Proxy HAL starting");
    info!("Intercepting AT commands via virtual serial port proxy");

    let filter = Arc::new(CommandFilter::default_secure());

    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path).context("Failed to bind baseband proxy socket")?;
    info!(socket = SOCKET_PATH, "Baseband proxy HAL listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let filter = Arc::clone(&filter);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, filter).await {
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
    filter: Arc<CommandFilter>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response: AtResponse = match serde_json::from_str::<AtRequest>(&line) {
            Err(e) => {
                warn!("Malformed AT request '{}': {}", line, e);
                AtResponse {
                    allowed: false,
                    forwarded_command: None,
                    reason: Some(format!("parse error: {}", e)),
                }
            }
            Ok(req) => {
                info!(uid = req.uid, command = %req.command, "AT command received");
                match ATCommand::parse(&req.command) {
                    Err(e) => {
                        warn!(uid = req.uid, "Malformed AT command: {}", e);
                        AtResponse {
                            allowed: false,
                            forwarded_command: None,
                            reason: Some(e.to_string()),
                        }
                    }
                    Ok(at_cmd) => {
                        let verdict = filter.evaluate(&at_cmd);
                        match verdict {
                            FilterVerdict::Allow => AtResponse {
                                allowed: true,
                                forwarded_command: Some(at_cmd.raw),
                                reason: None,
                            },
                            FilterVerdict::Sanitize(sanitized) => {
                                info!(
                                    uid = req.uid,
                                    original = %req.command,
                                    sanitized = %sanitized,
                                    "AT command sanitized"
                                );
                                AtResponse {
                                    allowed: true,
                                    forwarded_command: Some(sanitized),
                                    reason: Some("sanitized".into()),
                                }
                            }
                            FilterVerdict::Block => AtResponse {
                                allowed: false,
                                forwarded_command: None,
                                reason: Some(format!(
                                    "AT command '{}' blocked by policy",
                                    at_cmd.raw
                                )),
                            },
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
