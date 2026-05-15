mod profile;

use anyhow::Context;
use profile::{IsolationPolicy, Profile, ProfileKind, ProfileManager};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/hispashield/profileisolation.sock";
const CONFIG_FILE: &str = "/data/hispashield/profile_config.json";
const MOUNTS_POLL_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum IsolationRequest {
    CheckAccess { uid: u32, path: String },
    ListProfiles,
}

#[derive(Debug, Serialize)]
struct IsolationResponse {
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profiles: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("profile_isolation=debug".parse().unwrap()),
        )
        .json()
        .init();

    info!("HispaShield Profile Isolation starting");

    let mut manager = match profile::ProfileManager::load_from_file(CONFIG_FILE) {
        Ok(m) => {
            info!(count = m.profile_count(), "Profile config loaded");
            m
        }
        Err(e) => {
            warn!("Could not load profile config ({}), using built-in defaults", e);
            build_default_manager()
        }
    };

    let manager = Arc::new(Mutex::new(manager));

    // Spawn a task that periodically checks /proc/mounts for unexpected bind-mounts
    let manager_monitor = Arc::clone(&manager);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            std::time::Duration::from_secs(MOUNTS_POLL_INTERVAL_SECS),
        );
        loop {
            interval.tick().await;
            monitor_mounts(&manager_monitor).await;
        }
    });

    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path).context("Failed to bind profile-isolation socket")?;
    info!(socket = SOCKET_PATH, "Profile isolation daemon listening");

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
    manager: Arc<Mutex<ProfileManager>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response: IsolationResponse = match serde_json::from_str::<IsolationRequest>(&line) {
            Err(e) => {
                warn!("Parse error: {}", e);
                IsolationResponse { allowed: false, reason: Some(format!("parse error: {}", e)), profiles: None }
            }
            Ok(req) => {
                let mgr = manager.lock().await;
                match req {
                    IsolationRequest::CheckAccess { uid, path } => {
                        match mgr.check_path_access(uid, &path) {
                            Ok(()) => IsolationResponse { allowed: true, reason: None, profiles: None },
                            Err(e) => IsolationResponse {
                                allowed: false,
                                reason: Some(e.to_string()),
                                profiles: None,
                            },
                        }
                    }
                    IsolationRequest::ListProfiles => {
                        let names = mgr.profile_names();
                        IsolationResponse { allowed: true, reason: None, profiles: Some(names) }
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

async fn monitor_mounts(manager: &Arc<Mutex<ProfileManager>>) {
    // Read /proc/mounts and check for unexpected bind-mounts that cross profile boundaries
    let content = match tokio::fs::read_to_string("/proc/mounts").await {
        Ok(c) => c,
        Err(_) => return,
    };

    let mgr = manager.lock().await;
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let mount_point = fields[1];
        let options = fields[3];
        // Detect bind mounts that cross profile data roots
        if options.contains("bind") {
            let source = fields[0];
            let source_profile = mgr.profile_for_path(source);
            let dest_profile = mgr.profile_for_path(mount_point);
            if let (Some(sp), Some(dp)) = (source_profile, dest_profile) {
                if sp.id != dp.id {
                    warn!(
                        source,
                        mount_point,
                        source_profile = %sp.id,
                        dest_profile = %dp.id,
                        "ALERT: Cross-profile bind-mount detected!"
                    );
                }
            }
        }
    }
}

fn build_default_manager() -> ProfileManager {
    let policy = IsolationPolicy::default();
    let mut mgr = ProfileManager::new(policy);
    mgr.add_profile(Profile {
        id: "personal".into(),
        kind: ProfileKind::Personal,
        data_root: PathBuf::from("/data/user/0"),
        uid_range_start: 10000,
        uid_range_end: 19999,
    });
    mgr.add_profile(Profile {
        id: "work".into(),
        kind: ProfileKind::Work,
        data_root: PathBuf::from("/data/user/10"),
        uid_range_start: 1010000,
        uid_range_end: 1019999,
    });
    mgr.add_profile(Profile {
        id: "guest".into(),
        kind: ProfileKind::Guest,
        data_root: PathBuf::from("/data/user/11"),
        uid_range_start: 1110000,
        uid_range_end: 1119999,
    });
    mgr
}
