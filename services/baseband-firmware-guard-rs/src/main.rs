mod firmware;
mod imsi_catcher;

use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
    time,
};
use tracing::{error, info, warn};

use firmware::{CheckResult, FirmwareGuard};
use imsi_catcher::{CellObservation, ImsiCatcherDetector, ImsiCatcherRisk};

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request {
    /// Trigger an on-demand integrity check of all known firmware blobs.
    CheckIntegrity,
    /// Submit a new cell observation for IMSI Catcher analysis.
    AnalyzeSignal {
        rssi: i32,
        cell_id: u32,
        lac: u16,
        mcc: u16,
        mnc: u16,
        tech: String,
        #[serde(default)]
        timestamp: u64,
    },
    /// Return the cached results of the last firmware integrity check.
    GetLastResults,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Integrity {
        status: String,
        details: Vec<CheckResult>,
    },
    Signal {
        risk: ImsiCatcherRisk,
    },
    LastResults {
        status: String,
        details: Vec<CheckResult>,
        checked_at: u64,
    },
    Error {
        error: String,
    },
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct DaemonState {
    guard: FirmwareGuard,
    detector: ImsiCatcherDetector,
    last_results: Option<(Vec<CheckResult>, u64)>,
}

// ---------------------------------------------------------------------------
// Background integrity re-check task
// ---------------------------------------------------------------------------

async fn background_integrity_check(state: Arc<Mutex<DaemonState>>) {
    let check_interval = std::env::var("BBGUARD_CHECK_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3600);

    let mut interval = time::interval(time::Duration::from_secs(check_interval));
    // Skip the first tick (fires immediately) so we don't double-check on startup.
    interval.tick().await;

    loop {
        interval.tick().await;
        info!("background: starting firmware integrity re-check");
        let results = {
            let st = state.lock().await;
            // Must release lock before awaiting the potentially-long verify_all.
            // We clone the guard to avoid holding the mutex across await points.
            // FirmwareGuard does not implement Clone, so we re-acquire after
            // spawning the check.
            drop(st);
            // Re-lock briefly to run verification (acceptable since verify_all
            // is I/O-bound and we are in an async context).
            let st = state.lock().await;
            st.guard.verify_all().await
        };

        let tampered = results
            .iter()
            .any(|r| r.status == firmware::IntegrityStatus::Tampered);
        if tampered {
            warn!("BACKGROUND CHECK: firmware tampering detected!");
            // Attempt to notify the duress daemon via its Unix socket.
            notify_duress_daemon_of_tamper().await;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut st = state.lock().await;
        st.last_results = Some((results, now));
    }
}

/// Send a tamper alert to the duress daemon over its Unix socket.
/// Best-effort – errors are logged but not fatal.
async fn notify_duress_daemon_of_tamper() {
    use tokio::net::UnixStream;
    let duress_sock = "/run/hispashield/duress.sock";
    match UnixStream::connect(duress_sock).await {
        Err(e) => {
            warn!("could not connect to duress daemon at {duress_sock}: {e}");
        }
        Ok(mut stream) => {
            let msg = serde_json::json!({
                "action": "baseband_tamper_alert",
                "source": "baseband-firmware-guard"
            });
            let mut bytes = serde_json::to_vec(&msg).unwrap_or_default();
            bytes.push(b'\n');
            if let Err(e) = stream.write_all(&bytes).await {
                warn!("error notifying duress daemon: {e}");
            } else {
                info!("tamper alert sent to duress daemon");
            }
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
            Ok(Request::CheckIntegrity) => {
                let st = state.lock().await;
                let results = st.guard.verify_all().await;
                let status = FirmwareGuard::overall_status(&results).to_string();
                drop(st);

                // Cache results.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                {
                    let mut st = state.lock().await;
                    st.last_results = Some((results.clone(), now));
                }

                Response::Integrity {
                    status,
                    details: results,
                }
            }
            Ok(Request::AnalyzeSignal {
                rssi,
                cell_id,
                lac,
                mcc,
                mnc,
                tech,
                timestamp,
            }) => {
                let ts = if timestamp == 0 {
                    CellObservation::now_secs()
                } else {
                    timestamp
                };
                let obs = CellObservation {
                    rssi,
                    cell_id,
                    lac,
                    mcc,
                    mnc,
                    tech,
                    timestamp: ts,
                };
                let mut st = state.lock().await;
                st.detector.observe(obs);
                let risk = st.detector.analyze();
                Response::Signal { risk }
            }
            Ok(Request::GetLastResults) => {
                let st = state.lock().await;
                match &st.last_results {
                    None => Response::Error {
                        error: "no integrity check has been run yet".to_string(),
                    },
                    Some((results, ts)) => {
                        let status = FirmwareGuard::overall_status(results).to_string();
                        Response::LastResults {
                            status,
                            details: results.clone(),
                            checked_at: *ts,
                        }
                    }
                }
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

    let hash_db_path = std::env::var("BBGUARD_HASH_DB")
        .unwrap_or_else(|_| "/data/hispashield/firmware_hashes.json".to_string());

    let guard = FirmwareGuard::load(&hash_db_path)
        .with_context(|| format!("loading firmware hash database from {hash_db_path}"))?;

    // Run an initial integrity check on startup.
    info!("performing startup firmware integrity check");
    let initial_results = guard.verify_all().await;
    let initial_status = FirmwareGuard::overall_status(&initial_results);
    info!("startup integrity check result: {initial_status}");
    if initial_status == "tampered" {
        warn!("STARTUP: firmware tampering detected – alerting duress daemon");
        notify_duress_daemon_of_tamper().await;
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let state = Arc::new(Mutex::new(DaemonState {
        guard,
        detector: ImsiCatcherDetector::new(),
        last_results: Some((initial_results, now_secs)),
    }));

    // Start the background re-check task.
    let state_bg = Arc::clone(&state);
    tokio::spawn(background_integrity_check(state_bg));

    let sock_path = "/run/hispashield/bbguard.sock";
    let _ = std::fs::remove_file(sock_path);
    if let Some(parent) = std::path::Path::new(sock_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket dir {parent:?}"))?;
    }

    let listener = UnixListener::bind(sock_path)
        .with_context(|| format!("binding Unix socket {sock_path}"))?;

    info!("baseband-firmware-guard listening on {sock_path}");

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
    use firmware::{FirmwareGuard, FirmwareHash, IntegrityStatus};
    use imsi_catcher::ImsiCatcherDetector;

    #[test]
    fn test_request_parse_check_integrity() {
        let json = r#"{"action":"check_integrity"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::CheckIntegrity));
    }

    #[test]
    fn test_request_parse_analyze_signal() {
        let json = r#"{"action":"analyze_signal","rssi":-85,"cell_id":12345,"lac":678,"mcc":214,"mnc":7,"tech":"LTE"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::AnalyzeSignal { rssi, cell_id, tech, .. } => {
                assert_eq!(rssi, -85);
                assert_eq!(cell_id, 12345);
                assert_eq!(tech, "LTE");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_request_parse_get_last_results() {
        let json = r#"{"action":"get_last_results"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::GetLastResults));
    }

    #[test]
    fn test_overall_status_empty_is_unknown() {
        assert_eq!(FirmwareGuard::overall_status(&[]), "unknown");
    }

    #[test]
    fn test_imsi_detector_initial_state() {
        let det = ImsiCatcherDetector::new();
        let risk = det.analyze();
        assert_eq!(risk.score, 0);
    }

    #[tokio::test]
    async fn test_daemon_state_check_integrity_no_files() {
        let guard = FirmwareGuard::from_known_hashes(vec![FirmwareHash {
            path: "/nonexistent/modem.b00".to_string(),
            expected_sha256: "aabb".to_string(),
            description: "test".to_string(),
        }]);
        let state = Arc::new(Mutex::new(DaemonState {
            guard,
            detector: ImsiCatcherDetector::new(),
            last_results: None,
        }));
        let st = state.lock().await;
        let results = st.guard.verify_all().await;
        assert_eq!(results[0].status, IntegrityStatus::Missing);
    }

    #[test]
    fn test_error_response_serializes() {
        let resp = Response::Error {
            error: "something went wrong".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("something went wrong"));
    }

    #[test]
    fn test_signal_response_includes_risk() {
        let risk = ImsiCatcherRisk {
            score: 42,
            indicators: vec!["test indicator".to_string()],
            recommendation: "stay safe".to_string(),
        };
        let resp = Response::Signal { risk };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("42"));
        assert!(json.contains("test indicator"));
    }
}
