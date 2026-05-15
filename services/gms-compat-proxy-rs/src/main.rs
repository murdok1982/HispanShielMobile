mod proxy;

use anyhow::Context;
use proxy::{EndpointFilter, GmsProxy, GmsRequest};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/hispashield/gmscompat.sock";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("gms_compat_proxy=debug".parse().unwrap()),
        )
        .json()
        .init();

    info!("HispaShield GMS Compat Proxy starting");

    let proxy = Arc::new(GmsProxy::new(EndpointFilter::default_production()));

    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path).context("Failed to bind GMS compat socket")?;
    info!(socket = SOCKET_PATH, "GMS proxy listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let proxy = Arc::clone(&proxy);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, proxy).await {
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
    proxy: Arc<GmsProxy>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<GmsRequest>(&line) {
            Err(e) => {
                warn!("Failed to parse GMS request: {}", e);
                serde_json::json!({
                    "allowed": false,
                    "reason": format!("parse error: {}", e)
                })
            }
            Ok(req) => {
                let resp = proxy.process_request(req);
                serde_json::to_value(&resp)?
            }
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }
    Ok(())
}
