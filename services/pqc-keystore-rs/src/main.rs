//! PQC Keystore daemon — HispaShield Mobile
//!
//! Listens on a Unix-domain socket and dispatches newline-delimited JSON
//! requests to the `PqcKeystore` service. Each connection is handled in its
//! own Tokio task. The keystore state is shared via `Arc<Mutex<PqcKeystore>>`.

mod algorithms;
mod keystore;

use std::sync::Arc;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{error, info, instrument, warn};
use zeroize::Zeroizing;

use algorithms::Algorithm;
use keystore::{derive_master_key, PqcKeystore};

// ─── Configuration ─────────────────────────────────────────────────────────

const SOCKET_PATH: &str = "/run/hispashield/pqc-keystore.sock";
const STORE_DIR: &str = "/data/hispashield/pqc_keystore";

// ─── JSON protocol types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Request {
    action: String,
    /// Key ID for generate / sign / encapsulate / decapsulate / delete.
    key_id: Option<String>,
    /// Algorithm string for generate_keypair.
    algorithm: Option<String>,
    /// Base64-encoded data for sign.
    data: Option<String>,
    /// Base64-encoded recipient public key for encapsulate.
    recipient_public_key: Option<String>,
    /// Base64-encoded ciphertext for decapsulate.
    ciphertext: Option<String>,
}

#[derive(Debug, Serialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<keystore::KeySummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    fn ok() -> Self {
        Self {
            public_key: None,
            key_id: None,
            signature: None,
            algorithm: None,
            ciphertext: None,
            shared_secret: None,
            keys: None,
            deleted: None,
            error: None,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            error: Some(msg.into()),
            ..Self::ok()
        }
    }
}

// ─── Request dispatch ─────────────────────────────────────────────────────

/// Process a single JSON request and return the JSON response.
async fn handle_request(
    req: Request,
    store: Arc<Mutex<PqcKeystore>>,
) -> Response {
    match req.action.as_str() {
        "generate_keypair" => {
            let key_id = match req.key_id {
                Some(id) => id,
                None => return Response::err("Missing field: key_id"),
            };
            let algo_str = match req.algorithm {
                Some(a) => a,
                None => return Response::err("Missing field: algorithm"),
            };
            let algorithm = match Algorithm::from_str(&algo_str) {
                Ok(a) => a,
                Err(e) => return Response::err(format!("Invalid algorithm: {e}")),
            };
            let mut store = store.lock().await;
            match store.generate_and_store(&key_id, &algorithm) {
                Ok(pk) => Response {
                    public_key: Some(BASE64.encode(&pk)),
                    key_id: Some(key_id),
                    ..Response::ok()
                },
                Err(e) => Response::err(format!("generate_keypair failed: {e}")),
            }
        }

        "sign" => {
            let key_id = match req.key_id {
                Some(id) => id,
                None => return Response::err("Missing field: key_id"),
            };
            let data_b64 = match req.data {
                Some(d) => d,
                None => return Response::err("Missing field: data"),
            };
            let data = match BASE64.decode(&data_b64) {
                Ok(d) => d,
                Err(e) => return Response::err(format!("Invalid base64 data: {e}")),
            };
            let store = store.lock().await;
            match store.sign(&key_id, &data) {
                Ok(sig) => Response {
                    signature: Some(BASE64.encode(&sig)),
                    algorithm: Some("ML-DSA-65".to_string()),
                    ..Response::ok()
                },
                Err(e) => Response::err(format!("sign failed: {e}")),
            }
        }

        "encapsulate" => {
            let pk_b64 = match req.recipient_public_key {
                Some(p) => p,
                None => return Response::err("Missing field: recipient_public_key"),
            };
            let pk = match BASE64.decode(&pk_b64) {
                Ok(p) => p,
                Err(e) => return Response::err(format!("Invalid base64 recipient_public_key: {e}")),
            };
            let store = store.lock().await;
            match store.encapsulate(&pk) {
                Ok((ct, ss)) => Response {
                    ciphertext: Some(BASE64.encode(&ct)),
                    shared_secret: Some(BASE64.encode(&ss)),
                    ..Response::ok()
                },
                Err(e) => Response::err(format!("encapsulate failed: {e}")),
            }
        }

        "decapsulate" => {
            let key_id = match req.key_id {
                Some(id) => id,
                None => return Response::err("Missing field: key_id"),
            };
            let ct_b64 = match req.ciphertext {
                Some(c) => c,
                None => return Response::err("Missing field: ciphertext"),
            };
            let ct = match BASE64.decode(&ct_b64) {
                Ok(c) => c,
                Err(e) => return Response::err(format!("Invalid base64 ciphertext: {e}")),
            };
            let store = store.lock().await;
            match store.decapsulate(&key_id, &ct) {
                Ok(ss) => Response {
                    shared_secret: Some(BASE64.encode(&*ss)),
                    ..Response::ok()
                },
                Err(e) => Response::err(format!("decapsulate failed: {e}")),
            }
        }

        "list_keys" => {
            let store = store.lock().await;
            Response {
                keys: Some(store.list_keys()),
                ..Response::ok()
            }
        }

        "delete_key" => {
            let key_id = match req.key_id {
                Some(id) => id,
                None => return Response::err("Missing field: key_id"),
            };
            let mut store = store.lock().await;
            let deleted = store.delete(&key_id);
            Response {
                deleted: Some(deleted),
                key_id: Some(key_id),
                ..Response::ok()
            }
        }

        other => Response::err(format!("Unknown action: {other}")),
    }
}

// ─── Connection handler ────────────────────────────────────────────────────

async fn handle_connection(
    stream: tokio::net::UnixStream,
    store: Arc<Mutex<PqcKeystore>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                info!(action = %req.action, "Received request");
                handle_request(req, Arc::clone(&store)).await
            }
            Err(e) => {
                warn!("JSON parse error: {e}");
                Response::err(format!("JSON parse error: {e}"))
            }
        };

        let mut resp_json = match serde_json::to_string(&response) {
            Ok(j) => j,
            Err(e) => {
                error!("Failed to serialize response: {e}");
                format!("{{\"error\":\"serialization error: {e}\"}}"),
            }
        };
        resp_json.push('\n');

        if let Err(e) = writer.write_all(resp_json.as_bytes()).await {
            warn!("Failed to write response: {e}");
            break;
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    info!("pqc-keystore starting");

    // Ensure required directories exist
    std::fs::create_dir_all(STORE_DIR)
        .with_context(|| format!("Creating store dir: {STORE_DIR}"))?;

    if let Some(parent) = std::path::Path::new(SOCKET_PATH).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating socket dir: {:?}", parent))?;
    }

    // Remove stale socket
    let _ = std::fs::remove_file(SOCKET_PATH);

    // Derive master key (from simulated hardware)
    let master_key = derive_master_key(STORE_DIR)
        .context("Deriving master key")?;

    // Open keystore
    let store = PqcKeystore::open(STORE_DIR, master_key)
        .context("Opening keystore")?;
    let store = Arc::new(Mutex::new(store));

    // Bind Unix socket
    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("Binding socket: {SOCKET_PATH}"))?;

    info!(socket = SOCKET_PATH, "Listening for connections");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    handle_connection(stream, store).await;
                });
            }
            Err(e) => {
                error!("Accept error: {e}");
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_CTR: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: String,
    }
    impl TestDir {
        fn new() -> Self {
            let n = TEST_CTR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("pqc-main-test-{}-{}", std::process::id(), n))
                .to_str()
                .unwrap()
                .to_string();
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    async fn make_test_store() -> (TestDir, Arc<Mutex<PqcKeystore>>) {
        let dir = TestDir::new();
        let mk = Zeroizing::new(vec![0x42u8; 32]);
        let ks = PqcKeystore::open(&dir.path, mk).unwrap();
        (dir, Arc::new(Mutex::new(ks)))
    }

    #[tokio::test]
    async fn generate_keypair_action() {
        let (_dir, store) = make_test_store().await;
        let req = Request {
            action: "generate_keypair".to_string(),
            key_id: Some("k1".to_string()),
            algorithm: Some("ML-DSA-65".to_string()),
            data: None,
            recipient_public_key: None,
            ciphertext: None,
        };
        let resp = handle_request(req, store).await;
        assert!(resp.error.is_none());
        assert!(resp.public_key.is_some());
        assert_eq!(resp.key_id.as_deref(), Some("k1"));
    }

    #[tokio::test]
    async fn sign_action() {
        let (_dir, store) = make_test_store().await;

        // Generate key first
        let gen_req = Request {
            action: "generate_keypair".to_string(),
            key_id: Some("sign-k".to_string()),
            algorithm: Some("ML-DSA-65".to_string()),
            data: None,
            recipient_public_key: None,
            ciphertext: None,
        };
        handle_request(gen_req, Arc::clone(&store)).await;

        let data_b64 = BASE64.encode(b"hello hispashield");
        let sign_req = Request {
            action: "sign".to_string(),
            key_id: Some("sign-k".to_string()),
            algorithm: None,
            data: Some(data_b64),
            recipient_public_key: None,
            ciphertext: None,
        };
        let resp = handle_request(sign_req, store).await;
        assert!(resp.error.is_none(), "Error: {:?}", resp.error);
        assert!(resp.signature.is_some());
    }

    #[tokio::test]
    async fn list_keys_action() {
        let (_dir, store) = make_test_store().await;
        for name in &["a", "b", "c"] {
            let req = Request {
                action: "generate_keypair".to_string(),
                key_id: Some(name.to_string()),
                algorithm: Some("ML-KEM-768".to_string()),
                data: None,
                recipient_public_key: None,
                ciphertext: None,
            };
            handle_request(req, Arc::clone(&store)).await;
        }
        let list_req = Request {
            action: "list_keys".to_string(),
            key_id: None,
            algorithm: None,
            data: None,
            recipient_public_key: None,
            ciphertext: None,
        };
        let resp = handle_request(list_req, store).await;
        assert_eq!(resp.keys.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn delete_key_action() {
        let (_dir, store) = make_test_store().await;
        let gen = Request {
            action: "generate_keypair".to_string(),
            key_id: Some("del-me".to_string()),
            algorithm: Some("ML-KEM-768".to_string()),
            data: None,
            recipient_public_key: None,
            ciphertext: None,
        };
        handle_request(gen, Arc::clone(&store)).await;

        let del = Request {
            action: "delete_key".to_string(),
            key_id: Some("del-me".to_string()),
            algorithm: None,
            data: None,
            recipient_public_key: None,
            ciphertext: None,
        };
        let resp = handle_request(del, store).await;
        assert_eq!(resp.deleted, Some(true));
    }

    #[tokio::test]
    async fn unknown_action_returns_error() {
        let (_dir, store) = make_test_store().await;
        let req = Request {
            action: "fly_to_moon".to_string(),
            key_id: None,
            algorithm: None,
            data: None,
            recipient_public_key: None,
            ciphertext: None,
        };
        let resp = handle_request(req, store).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn encapsulate_action() {
        let (_dir, store) = make_test_store().await;
        let gen = Request {
            action: "generate_keypair".to_string(),
            key_id: Some("kem-recv".to_string()),
            algorithm: Some("ML-KEM-768".to_string()),
            data: None,
            recipient_public_key: None,
            ciphertext: None,
        };
        let gen_resp = handle_request(gen, Arc::clone(&store)).await;
        let pk_b64 = gen_resp.public_key.unwrap();

        let enc_req = Request {
            action: "encapsulate".to_string(),
            key_id: None,
            algorithm: Some("ML-KEM-768".to_string()),
            data: None,
            recipient_public_key: Some(pk_b64),
            ciphertext: None,
        };
        let enc_resp = handle_request(enc_req, store).await;
        assert!(enc_resp.error.is_none());
        assert!(enc_resp.ciphertext.is_some());
        assert!(enc_resp.shared_secret.is_some());
    }
}
