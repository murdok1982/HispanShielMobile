mod esim;
mod triangulation;

use anyhow::Result;
use chrono::Utc;
use esim::{EsimManager, EsimProfile, EsimRotationConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use triangulation::AntiTriangulationEngine;

// ---------------------------------------------------------------------------
// Daemon state
// ---------------------------------------------------------------------------

struct DaemonState {
    manager: Option<EsimManager>,
    anti_tri: AntiTriangulationEngine,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            manager: None,
            anti_tri: AntiTriangulationEngine::new(),
        }
    }
}

type SharedState = Arc<Mutex<DaemonState>>;

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request {
    Status,
    Rotate,
    Configure {
        rotation_interval_hours: Option<u64>,
        profiles: Option<Vec<EsimProfile>>,
        randomize: Option<bool>,
    },
    AddProfile {
        profile: EsimProfile,
    },
    AssessRisk,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Ok {
        ok: bool,
        message: String,
    },
    Status {
        current_profile: Option<EsimProfile>,
        rotation_interval_secs: Option<u64>,
        time_until_next_rotation_secs: Option<u64>,
        last_rotation_timestamp: String,
        profile_count: usize,
    },
    Risk {
        risk_level: String,
        reasons: Vec<String>,
        recommended_action: String,
    },
    Error {
        error: String,
    },
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
        Request::Status => {
            let st = state.lock().await;
            match &st.manager {
                None => Response::Status {
                    current_profile: None,
                    rotation_interval_secs: None,
                    time_until_next_rotation_secs: None,
                    last_rotation_timestamp: "never".to_string(),
                    profile_count: 0,
                },
                Some(mgr) => {
                    let current = mgr.current().clone();
                    let interval = mgr.config.rotation_interval_seconds;
                    let until_next = mgr.time_until_next_rotation().as_secs();
                    let profile_count = mgr.config.profiles.len();
                    Response::Status {
                        current_profile: Some(current),
                        rotation_interval_secs: Some(interval),
                        time_until_next_rotation_secs: Some(until_next),
                        last_rotation_timestamp: Utc::now().to_rfc3339(),
                        profile_count,
                    }
                }
            }
        }

        Request::Rotate => {
            let mut st = state.lock().await;
            match &mut st.manager {
                None => Response::Error {
                    error: "No eSIM manager configured. Send 'configure' first.".to_string(),
                },
                Some(mgr) => {
                    if mgr.config.profiles.len() < 2 {
                        return Response::Error {
                            error: "At least 2 profiles required for rotation.".to_string(),
                        };
                    }
                    match mgr.apply_rotation().await {
                        Err(e) => Response::Error {
                            error: format!("Rotation failed: {e}"),
                        },
                        Ok(()) => {
                            let profile = mgr.current().clone();
                            // Record in anti-triangulation engine
                            st.anti_tri.record_rotation(&profile.iccid);
                            Response::Ok {
                                ok: true,
                                message: format!(
                                    "Rotated to profile '{}' (ICCID: {})",
                                    profile.nickname, profile.iccid
                                ),
                            }
                        }
                    }
                }
            }
        }

        Request::Configure {
            rotation_interval_hours,
            profiles,
            randomize,
        } => {
            let mut st = state.lock().await;

            let interval_secs = rotation_interval_hours.unwrap_or(1) * 3600;
            let profiles = profiles.unwrap_or_default();
            let randomize = randomize.unwrap_or(true);

            let config = EsimRotationConfig {
                profiles,
                rotation_interval_seconds: interval_secs,
                randomize_jitter: randomize,
                jitter_seconds: 1800,
            };

            let profile_count = config.profiles.len();
            st.manager = Some(EsimManager::new(config));

            info!(
                interval_secs = interval_secs,
                profile_count = profile_count,
                randomize = randomize,
                "eSIM manager configured"
            );
            Response::Ok {
                ok: true,
                message: format!(
                    "Configured with {profile_count} profiles, interval {}s, jitter {}",
                    interval_secs,
                    if randomize { "enabled" } else { "disabled" }
                ),
            }
        }

        Request::AddProfile { profile } => {
            let mut st = state.lock().await;
            match &mut st.manager {
                None => {
                    // Create a manager with just this profile
                    let config = EsimRotationConfig {
                        profiles: vec![profile.clone()],
                        ..EsimRotationConfig::default()
                    };
                    st.manager = Some(EsimManager::new(config));
                    info!(profile_id = %profile.id, "Created manager with first profile");
                    Response::Ok {
                        ok: true,
                        message: format!("Profile '{}' added (new manager created)", profile.nickname),
                    }
                }
                Some(mgr) => {
                    let nickname = profile.nickname.clone();
                    mgr.config.profiles.push(profile);
                    info!(nickname = %nickname, "Added eSIM profile");
                    Response::Ok {
                        ok: true,
                        message: format!("Profile '{nickname}' added"),
                    }
                }
            }
        }

        Request::AssessRisk => {
            let st = state.lock().await;
            let assessment = st.anti_tri.assess_risk();
            Response::Risk {
                risk_level: assessment.risk_level.to_string(),
                reasons: assessment.reasons,
                recommended_action: assessment.recommended_action,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Background rotation task
// ---------------------------------------------------------------------------

async fn rotation_scheduler(state: SharedState) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        let mut st = state.lock().await;
        let should = st
            .manager
            .as_ref()
            .map(|m| m.should_rotate())
            .unwrap_or(false);

        if should {
            if let Some(mgr) = &mut st.manager {
                info!("Scheduled rotation triggered");
                match mgr.apply_rotation().await {
                    Ok(()) => {
                        let iccid = mgr.current().iccid.clone();
                        st.anti_tri.record_rotation(&iccid);
                    }
                    Err(e) => {
                        error!(err = %e, "Scheduled rotation failed");
                    }
                }
            }
        }

        // Periodic risk assessment log
        let risk = st.anti_tri.assess_risk();
        if risk.risk_level >= triangulation::RiskLevel::High {
            warn!(
                risk_level = %risk.risk_level,
                reasons = ?risk.reasons,
                "Anti-triangulation risk elevated"
            );
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
                .add_directive("esim_manager=debug".parse().unwrap()),
        )
        .json()
        .init();

    let socket_path = "/run/hispashield/esim.sock";

    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = UnixListener::bind(socket_path)?;
    info!(socket = socket_path, "eSIM manager daemon listening");

    let state: SharedState = Arc::new(Mutex::new(DaemonState::new()));

    tokio::spawn(rotation_scheduler(Arc::clone(&state)));

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
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

    fn sample_profile(id: &str) -> EsimProfile {
        EsimProfile {
            id: id.to_string(),
            nickname: format!("nick-{id}"),
            iccid: format!("89014103211118{}", id.chars().take(6).collect::<String>()),
            operator: "TestNet".to_string(),
            country: "ES".to_string(),
            active: false,
        }
    }

    #[test]
    fn test_request_deserialize_status() {
        let json = r#"{"action":"status"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Status));
    }

    #[test]
    fn test_request_deserialize_rotate() {
        let json = r#"{"action":"rotate"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Rotate));
    }

    #[test]
    fn test_request_deserialize_configure() {
        let json = r#"{"action":"configure","rotation_interval_hours":2,"randomize":true}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::Configure {
                rotation_interval_hours,
                randomize,
                ..
            } => {
                assert_eq!(rotation_interval_hours, Some(2));
                assert_eq!(randomize, Some(true));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_request_deserialize_add_profile() {
        let json = r#"{"action":"add_profile","profile":{"id":"p1","nickname":"alfa","iccid":"89014103","operator":"Op","country":"ES","active":false}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::AddProfile { .. }));
    }

    #[tokio::test]
    async fn test_process_status_no_manager() {
        let state = Arc::new(Mutex::new(DaemonState::new()));
        let resp = process_request(Request::Status, Arc::clone(&state)).await;
        match resp {
            Response::Status { profile_count, .. } => {
                assert_eq!(profile_count, 0);
            }
            _ => panic!("expected Status"),
        }
    }

    #[tokio::test]
    async fn test_process_configure_then_status() {
        let state = Arc::new(Mutex::new(DaemonState::new()));
        let profiles = vec![sample_profile("001"), sample_profile("002")];
        let configure = Request::Configure {
            rotation_interval_hours: Some(2),
            profiles: Some(profiles),
            randomize: Some(false),
        };
        let resp = process_request(configure, Arc::clone(&state)).await;
        assert!(matches!(resp, Response::Ok { .. }));

        let status_resp = process_request(Request::Status, Arc::clone(&state)).await;
        match status_resp {
            Response::Status { profile_count, rotation_interval_secs, .. } => {
                assert_eq!(profile_count, 2);
                assert_eq!(rotation_interval_secs, Some(7200));
            }
            _ => panic!("expected Status"),
        }
    }

    #[tokio::test]
    async fn test_rotate_no_manager_returns_error() {
        let state = Arc::new(Mutex::new(DaemonState::new()));
        let resp = process_request(Request::Rotate, Arc::clone(&state)).await;
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[tokio::test]
    async fn test_add_profile_creates_manager() {
        let state = Arc::new(Mutex::new(DaemonState::new()));
        let resp = process_request(
            Request::AddProfile {
                profile: sample_profile("p1"),
            },
            Arc::clone(&state),
        )
        .await;
        assert!(matches!(resp, Response::Ok { .. }));
        let st = state.lock().await;
        assert!(st.manager.is_some());
    }

    #[tokio::test]
    async fn test_assess_risk_no_history() {
        let state = Arc::new(Mutex::new(DaemonState::new()));
        let resp = process_request(Request::AssessRisk, Arc::clone(&state)).await;
        match resp {
            Response::Risk { risk_level, .. } => {
                assert_eq!(risk_level, "Critical");
            }
            _ => panic!("expected Risk"),
        }
    }

    #[test]
    fn test_response_error_serializes() {
        let resp = Response::Error {
            error: "test".to_string(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("test"));
    }
}
