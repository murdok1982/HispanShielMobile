mod attestation;
mod trust_store;

use anyhow::Result;
use attestation::AttestationEngine;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use trust_store::TrustStore;

// ---------------------------------------------------------------------------
// Daemon state
// ---------------------------------------------------------------------------

struct AttestationDaemon {
    engine: AttestationEngine,
    trust_store: TrustStore,
    last_attestation: Option<String>, // ISO-8601 timestamp
}

impl AttestationDaemon {
    fn new() -> Self {
        let engine = AttestationEngine::new(
            "/etc/hispashield/attestation-key.bin",
            "/etc/hispashield/cert-chain.pem",
            "hispashield-1.0.0",
        );
        let trust_store = TrustStore::load("/var/lib/hispashield/trust-store.json")
            .unwrap_or_else(|e| {
                warn!(err = %e, "Could not load trust store; starting empty");
                TrustStore {
                    trusted_servers: std::collections::HashMap::new(),
                    store_path: "/var/lib/hispashield/trust-store.json".to_string(),
                }
            });

        Self {
            engine,
            trust_store,
            last_attestation: None,
        }
    }
}

type SharedState = Arc<Mutex<AttestationDaemon>>;

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request {
    GetAttestation {
        nonce: String,
        server_id: String,
    },
    VerifyServer {
        server_id: String,
        server_cert_pem: String,
    },
    AddTrustedServer {
        server_id: String,
        server_cert_pem: String,
    },
    Status,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Attestation {
        ok: bool,
        server_id: String,
        report: serde_json::Value,
    },
    ServerVerification {
        ok: bool,
        trusted: bool,
        server_id: String,
    },
    Status {
        last_attestation: Option<String>,
        trusted_servers: usize,
        attestation_valid: bool,
        hispashield_version: String,
        boot_state: String,
    },
    Ok {
        ok: bool,
        message: String,
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
        Request::GetAttestation { nonce, server_id } => {
            // Validate nonce is non-empty base64
            if nonce.is_empty() {
                return Response::Error {
                    error: "nonce must not be empty".to_string(),
                };
            }
            if BASE64.decode(&nonce).is_err() {
                return Response::Error {
                    error: "nonce must be valid base64".to_string(),
                };
            }

            let mut st = state.lock().await;
            match st.engine.generate_report(&nonce).await {
                Err(e) => {
                    error!(err = %e, "Failed to generate attestation report");
                    Response::Error {
                        error: format!("attestation failed: {e}"),
                    }
                }
                Ok(report) => {
                    let timestamp = Utc::now().to_rfc3339();
                    st.last_attestation = Some(timestamp.clone());
                    // Touch the server's last-seen time
                    st.trust_store.touch(&server_id);

                    // Serialise report to a generic JSON value for the response
                    let report_value = serde_json::to_value(&report).unwrap_or(serde_json::Value::Null);
                    info!(server_id = %server_id, "Attestation report generated");
                    Response::Attestation {
                        ok: true,
                        server_id,
                        report: report_value,
                    }
                }
            }
        }

        Request::VerifyServer {
            server_id,
            server_cert_pem,
        } => {
            let mut st = state.lock().await;
            let trusted = st.trust_store.verify_server(&server_id, &server_cert_pem);
            if trusted {
                st.trust_store.touch(&server_id);
            }
            Response::ServerVerification {
                ok: true,
                trusted,
                server_id,
            }
        }

        Request::AddTrustedServer {
            server_id,
            server_cert_pem,
        } => {
            let mut st = state.lock().await;
            match st.trust_store.add_server(&server_id, &server_cert_pem) {
                Err(e) => Response::Error {
                    error: format!("add server failed: {e}"),
                },
                Ok(()) => {
                    // Persist (best-effort)
                    if let Err(e) = st.trust_store.save() {
                        warn!(err = %e, "Failed to persist trust store");
                    }
                    Response::Ok {
                        ok: true,
                        message: format!("Server '{server_id}' added to trust store"),
                    }
                }
            }
        }

        Request::Status => {
            let st = state.lock().await;
            let boot_state = format!("{:?}", st.engine.get_boot_state());
            let trusted_count = st.trust_store.trusted_count();
            let last = st.last_attestation.clone();
            Response::Status {
                last_attestation: last,
                trusted_servers: trusted_count,
                attestation_valid: true,
                hispashield_version: st.engine.hispashield_version.clone(),
                boot_state,
            }
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
                .add_directive("remote_attestation=debug".parse().unwrap()),
        )
        .json()
        .init();

    let socket_path = "/run/hispashield/attestation.sock";

    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = UnixListener::bind(socket_path)?;
    info!(socket = socket_path, "Remote attestation daemon listening");

    let state: SharedState = Arc::new(Mutex::new(AttestationDaemon::new()));

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

    fn make_state() -> SharedState {
        Arc::new(Mutex::new(AttestationDaemon::new()))
    }

    #[test]
    fn test_request_deserialize_get_attestation() {
        let json = r#"{"action":"get_attestation","nonce":"dGVzdA==","server_id":"srv1"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::GetAttestation { nonce, server_id } => {
                assert_eq!(nonce, "dGVzdA==");
                assert_eq!(server_id, "srv1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_request_deserialize_verify_server() {
        let json = r#"{"action":"verify_server","server_id":"s1","server_cert_pem":"-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::VerifyServer { .. }));
    }

    #[test]
    fn test_request_deserialize_status() {
        let json = r#"{"action":"status"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Status));
    }

    #[test]
    fn test_request_deserialize_add_trusted_server() {
        let json = r#"{"action":"add_trusted_server","server_id":"s2","server_cert_pem":"pem"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::AddTrustedServer { .. }));
    }

    #[tokio::test]
    async fn test_process_status() {
        let state = make_state();
        let resp = process_request(Request::Status, Arc::clone(&state)).await;
        match resp {
            Response::Status {
                trusted_servers,
                attestation_valid,
                ..
            } => {
                assert_eq!(trusted_servers, 0);
                assert!(attestation_valid);
            }
            _ => panic!("expected Status"),
        }
    }

    #[tokio::test]
    async fn test_get_attestation_empty_nonce_error() {
        let state = make_state();
        let resp = process_request(
            Request::GetAttestation {
                nonce: "".to_string(),
                server_id: "srv".to_string(),
            },
            state,
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[tokio::test]
    async fn test_get_attestation_invalid_base64_error() {
        let state = make_state();
        let resp = process_request(
            Request::GetAttestation {
                nonce: "!!!not-base64!!!".to_string(),
                server_id: "srv".to_string(),
            },
            state,
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[tokio::test]
    async fn test_get_attestation_valid_nonce() {
        let state = make_state();
        // "test-nonce" base64
        let nonce = BASE64.encode(b"test-nonce-12345");
        let resp = process_request(
            Request::GetAttestation {
                nonce,
                server_id: "test-server".to_string(),
            },
            Arc::clone(&state),
        )
        .await;
        match resp {
            Response::Attestation { ok, server_id, report } => {
                assert!(ok);
                assert_eq!(server_id, "test-server");
                assert!(report.get("version").is_some());
                assert!(report.get("signature").is_some());
            }
            Response::Error { error } => panic!("unexpected error: {error}"),
            _ => panic!("unexpected response variant"),
        }
    }

    #[tokio::test]
    async fn test_verify_server_unknown_returns_false() {
        let state = make_state();
        let resp = process_request(
            Request::VerifyServer {
                server_id: "unknown".to_string(),
                server_cert_pem: "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n"
                    .to_string(),
            },
            state,
        )
        .await;
        match resp {
            Response::ServerVerification { trusted, .. } => {
                assert!(!trusted);
            }
            _ => panic!("expected ServerVerification"),
        }
    }

    #[tokio::test]
    async fn test_add_then_verify_server() {
        let state = make_state();
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n".to_string();
        let add_resp = process_request(
            Request::AddTrustedServer {
                server_id: "srv-verify".to_string(),
                server_cert_pem: pem.clone(),
            },
            Arc::clone(&state),
        )
        .await;
        assert!(matches!(add_resp, Response::Ok { .. }));

        let verify_resp = process_request(
            Request::VerifyServer {
                server_id: "srv-verify".to_string(),
                server_cert_pem: pem,
            },
            Arc::clone(&state),
        )
        .await;
        match verify_resp {
            Response::ServerVerification { trusted, .. } => {
                assert!(trusted);
            }
            _ => panic!("expected ServerVerification"),
        }
    }

    #[test]
    fn test_response_error_serializes() {
        let resp = Response::Error {
            error: "something went wrong".to_string(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("something went wrong"));
    }

    #[test]
    fn test_base64_nonce_validation() {
        assert!(BASE64.decode("dGVzdA==").is_ok());
        assert!(BASE64.decode("!!!").is_err());
    }
}
