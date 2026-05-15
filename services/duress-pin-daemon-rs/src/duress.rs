use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use tokio::fs;
use tracing::{debug, info, warn};

/// Configuration for the duress PIN daemon, loaded from JSON on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressConfig {
    /// SHA-256 hex digest of the normal (legitimate) PIN.
    pub normal_pin_hash: String,
    /// SHA-256 hex digest of the duress (panic) PIN.
    pub duress_pin_hash: String,
    /// UDP address to send encrypted distress beacons to, e.g. "1.2.3.4:9999".
    pub beacon_addr: String,
    /// Hex-encoded XOR key used to obfuscate the beacon payload.
    pub beacon_key: String,
    /// Filesystem path containing cryptographic key material to wipe on duress.
    pub keys_path: String,
    /// Path to decoy data shown to the attacker after duress is triggered.
    pub decoy_data_path: String,
}

impl DuressConfig {
    /// Load configuration from a JSON file at `path`.
    pub async fn load(path: &str) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)
            .await
            .with_context(|| format!("reading duress config from {path}"))?;
        let cfg: DuressConfig =
            serde_json::from_str(&raw).with_context(|| "parsing duress config JSON")?;
        Ok(cfg)
    }
}

/// The outcome of a PIN verification attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum PinResult {
    /// PIN matches the normal (legitimate) hash.
    Normal,
    /// PIN matches the duress (panic) hash – silent distress response triggered.
    Duress,
    /// PIN matches neither hash.
    Invalid,
}

/// Core engine handling PIN verification and duress response logic.
pub struct DuressEngine {
    config: DuressConfig,
}

impl DuressEngine {
    pub fn new(config: DuressConfig) -> Self {
        Self { config }
    }

    /// Return a reference to the current configuration.
    pub fn config(&self) -> &DuressConfig {
        &self.config
    }

    /// Compare `pin_hash` against known hashes.
    /// Uses constant-time string comparison to resist timing attacks.
    pub fn verify_pin(&self, pin_hash: &str) -> PinResult {
        let pin_bytes = pin_hash.as_bytes();
        let normal_bytes = self.config.normal_pin_hash.as_bytes();
        let duress_bytes = self.config.duress_pin_hash.as_bytes();

        // Compare both hashes in constant time (same length required for real CT compare;
        // SHA-256 hex is always 64 bytes, so this is safe here).
        let matches_normal = constant_time_eq(pin_bytes, normal_bytes);
        let matches_duress = constant_time_eq(pin_bytes, duress_bytes);

        if matches_duress {
            PinResult::Duress
        } else if matches_normal {
            PinResult::Normal
        } else {
            PinResult::Invalid
        }
    }

    /// Trigger the full duress response: wipe keys and send distress beacon.
    ///
    /// This is intentionally fire-and-forget from the caller's perspective;
    /// errors are logged but NOT propagated to the socket client so that the
    /// response remains indistinguishable from a normal PIN acceptance.
    pub async fn trigger_duress(&self) -> anyhow::Result<()> {
        // NOTE: intentionally no local audit log – deny traces.
        // Send beacon first (best-effort network exfil before disk wipe).
        if let Err(e) = self.send_beacon().await {
            // Suppress – do not leave traces in local logs.
            let _ = e;
        }
        self.wipe_keys().await?;
        Ok(())
    }

    /// Recursively delete all key material under `config.keys_path`.
    async fn wipe_keys(&self) -> anyhow::Result<()> {
        let path = &self.config.keys_path;
        match fs::remove_dir_all(path).await {
            Ok(()) => {
                debug!("key material removed");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already wiped or never existed – acceptable.
                debug!("keys_path not found, nothing to wipe");
            }
            Err(e) => {
                return Err(e).with_context(|| format!("wiping keys at {path}"));
            }
        }
        Ok(())
    }

    /// Build and send a compact XOR-obfuscated UDP distress beacon.
    ///
    /// Beacon payload (plaintext before XOR):
    ///   `DURESS:<unix_timestamp_secs>`
    ///
    /// The XOR key is repeated (key stream) over the full payload length.
    async fn send_beacon(&self) -> anyhow::Result<()> {
        let key_bytes =
            hex::decode(&self.config.beacon_key).with_context(|| "decoding beacon_key hex")?;
        if key_bytes.is_empty() {
            anyhow::bail!("beacon_key must not be empty");
        }

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let plaintext = format!("DURESS:{ts}");
        let plaintext_bytes = plaintext.as_bytes();

        // XOR encrypt with repeating key.
        let ciphertext: Vec<u8> = plaintext_bytes
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
            .collect();

        // Use blocking UDP send in a spawn_blocking context to avoid
        // blocking the async runtime on network I/O.
        let addr = self.config.beacon_addr.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let sock = UdpSocket::bind("0.0.0.0:0").with_context(|| "binding UDP socket")?;
            sock.send_to(&ciphertext, &addr)
                .with_context(|| format!("sending beacon to {addr}"))?;
            Ok(())
        })
        .await
        .with_context(|| "spawn_blocking for UDP beacon")??;

        info!("distress beacon dispatched");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Constant-time byte-slice comparison to resist timing side-channels.
// ---------------------------------------------------------------------------

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sha256_hex(s: &str) -> String {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        hex::encode(h.finalize())
    }

    fn make_engine(normal: &str, duress: &str) -> DuressEngine {
        DuressEngine::new(DuressConfig {
            normal_pin_hash: sha256_hex(normal),
            duress_pin_hash: sha256_hex(duress),
            beacon_addr: "127.0.0.1:19999".to_string(),
            beacon_key: hex::encode(b"testkey"),
            keys_path: "/tmp/hispashield_test_keys".to_string(),
            decoy_data_path: "/tmp/hispashield_decoy".to_string(),
        })
    }

    #[test]
    fn test_normal_pin_detected() {
        let engine = make_engine("1234", "9999");
        assert_eq!(engine.verify_pin(&sha256_hex("1234")), PinResult::Normal);
    }

    #[test]
    fn test_duress_pin_detected() {
        let engine = make_engine("1234", "9999");
        assert_eq!(engine.verify_pin(&sha256_hex("9999")), PinResult::Duress);
    }

    #[test]
    fn test_invalid_pin_detected() {
        let engine = make_engine("1234", "9999");
        assert_eq!(engine.verify_pin(&sha256_hex("0000")), PinResult::Invalid);
    }

    #[test]
    fn test_hashes_not_equal() {
        // Normal and duress PINs must hash differently.
        let engine = make_engine("1234", "9999");
        assert_ne!(engine.config.normal_pin_hash, engine.config.duress_pin_hash);
    }

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"hi", b"hii"));
    }

    #[tokio::test]
    async fn test_wipe_keys_missing_path_is_ok() {
        let engine = make_engine("1234", "9999");
        // Path does not exist – should succeed silently.
        let result = engine.wipe_keys().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wipe_keys_removes_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_str().unwrap().to_string();
        // Write a dummy key file.
        std::fs::write(format!("{path}/key.bin"), b"deadbeef").unwrap();

        let engine = DuressEngine::new(DuressConfig {
            normal_pin_hash: String::new(),
            duress_pin_hash: String::new(),
            beacon_addr: "127.0.0.1:19999".to_string(),
            beacon_key: hex::encode(b"k"),
            keys_path: path.clone(),
            decoy_data_path: String::new(),
        });

        engine.wipe_keys().await.unwrap();
        assert!(!std::path::Path::new(&path).exists());
    }
}
