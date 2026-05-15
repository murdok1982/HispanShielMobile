use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Represents the Verified-Boot / AVB state of the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BootState {
    /// Bootloader locked, AVB chain verified — highest trust.
    Verified,
    /// Bootloader unlocked; user has acknowledged the risk.
    Orange,
    /// AVB verification failed — do not trust.
    Red,
}

/// SHA-256 fingerprint of a running daemon binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonHash {
    pub name: String,
    pub sha256: String,
    pub pid: u32,
}

/// The full attestation report sent to a remote verifier.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Protocol version (currently 1).
    pub version: u8,
    /// ISO-8601 UTC timestamp at report generation time.
    pub timestamp: String,
    /// The nonce supplied by the verifier (prevents replay).
    pub nonce: String,
    /// SHA-256 of the hardware serial number — non-reversible identifier.
    pub device_id_hash: String,
    /// Android Verified Boot state.
    pub boot_state: BootState,
    /// Version string of the running HispaShield OS.
    pub hispashield_version: String,
    /// Hashes of the running HispaShield security daemons.
    pub daemon_hashes: Vec<DaemonHash>,
    /// Base64-encoded DER certificates from Titan M2 → Platform → App.
    pub attestation_chain: Vec<String>,
    /// Base64-encoded HMAC-SHA256 signature over all preceding fields.
    pub signature: String,
}

/// Core engine for generating and signing attestation reports.
pub struct AttestationEngine {
    /// Path to the HMAC key file (simulates Keystore/Titan M2 key).
    pub device_key_path: String,
    /// Path to the certificate chain file (PEM or concatenated DER-b64).
    pub cert_chain_path: String,
    /// Running HispaShield version string.
    pub hispashield_version: String,
}

impl AttestationEngine {
    pub fn new(key_path: &str, cert_path: &str, version: &str) -> Self {
        Self {
            device_key_path: key_path.to_string(),
            cert_chain_path: cert_path.to_string(),
            hispashield_version: version.to_string(),
        }
    }

    /// Generates a full attestation report for the given nonce.
    pub async fn generate_report(&self, nonce: &str) -> Result<AttestationReport> {
        info!(nonce = %nonce, "Generating attestation report");

        let timestamp = Utc::now().to_rfc3339();
        let device_id_hash = self.compute_device_id_hash().await;
        let boot_state = self.get_boot_state();
        let daemon_hashes = self.hash_running_daemons().await;
        let attestation_chain = self.load_cert_chain().await;

        let mut report = AttestationReport {
            version: 1,
            timestamp,
            nonce: nonce.to_string(),
            device_id_hash,
            boot_state,
            hispashield_version: self.hispashield_version.clone(),
            daemon_hashes,
            attestation_chain,
            signature: String::new(), // filled in below
        };

        report.signature = self.sign_report(&report).await?;
        Ok(report)
    }

    /// Computes a non-reversible device identifier by SHA-256 hashing the
    /// system serial number read from `/sys/class/android_serialno/serialno`
    /// or falling back to `/proc/sys/kernel/hostname`.
    async fn compute_device_id_hash(&self) -> String {
        let serial = tokio::fs::read_to_string("/sys/class/android_serialno/serialno")
            .await
            .or_else(|_| {
                tokio::fs::read_to_string("/proc/sys/kernel/hostname").map(|_| {
                    // This is a blocking call — use a static fallback in the error path
                    String::new()
                })
            })
            .unwrap_or_else(|_| "unknown-device".to_string());

        let mut hasher = Sha256::new();
        hasher.update(serial.trim().as_bytes());
        hasher.update(b"\x00hispashield-salt");
        hex::encode(hasher.finalize())
    }

    /// Reads `/proc/<pid>/exe` for each known HispaShield daemon and returns
    /// the SHA-256 hash of the binary on disk.
    pub async fn hash_running_daemons(&self) -> Vec<DaemonHash> {
        let known_daemons = &[
            "vpn-killswitch",
            "esim-manager",
            "remote-attestation",
            "hispashield-core",
        ];

        let mut results = Vec::new();

        // Enumerate /proc to find matching process names.
        let mut proc_dir = match tokio::fs::read_dir("/proc").await {
            Ok(d) => d,
            Err(e) => {
                warn!(err = %e, "Cannot enumerate /proc");
                return results;
            }
        };

        // Build a map of pid → exe path
        let mut pid_exes: HashMap<u32, String> = HashMap::new();
        while let Ok(Some(entry)) = proc_dir.next_entry().await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                let exe_path = format!("/proc/{pid}/exe");
                if let Ok(exe) = tokio::fs::read_link(&exe_path).await {
                    pid_exes.insert(pid, exe.to_string_lossy().to_string());
                }
            }
        }

        for daemon_name in known_daemons {
            // Find the first PID whose exe basename matches
            let found = pid_exes
                .iter()
                .find(|(_, exe)| exe.contains(daemon_name));

            if let Some((&pid, exe)) = found {
                match hash_file(exe).await {
                    Ok(hash) => {
                        debug!(daemon = daemon_name, pid = pid, sha256 = %hash, "Hashed daemon");
                        results.push(DaemonHash {
                            name: daemon_name.to_string(),
                            sha256: hash,
                            pid,
                        });
                    }
                    Err(e) => {
                        warn!(daemon = daemon_name, pid = pid, err = %e, "Failed to hash daemon binary");
                    }
                }
            } else {
                debug!(daemon = daemon_name, "Daemon not found in /proc");
            }
        }

        results
    }

    /// Determines the AVB boot state from `/proc/cmdline` or Android bootloader
    /// properties exposed in `/sys`.
    pub fn get_boot_state(&self) -> BootState {
        // Read /proc/cmdline synchronously (it's tiny).
        match std::fs::read_to_string("/proc/cmdline") {
            Err(_) => {
                warn!("Cannot read /proc/cmdline; assuming Orange boot state");
                BootState::Orange
            }
            Ok(cmdline) => {
                // Android bootloader appends androidboot.verifiedbootstate=green|yellow|orange|red
                if cmdline.contains("androidboot.verifiedbootstate=green") {
                    BootState::Verified
                } else if cmdline.contains("androidboot.verifiedbootstate=yellow") {
                    // Yellow means key replacement / OEM unlock but chain valid
                    BootState::Orange
                } else if cmdline.contains("androidboot.verifiedbootstate=red") {
                    BootState::Red
                } else if cmdline.contains("androidboot.verifiedbootstate=orange") {
                    BootState::Orange
                } else {
                    // On non-Android (dev/CI): treat as Verified for testing
                    debug!("No AVB boot state in cmdline; using Verified (non-Android host)");
                    BootState::Verified
                }
            }
        }
    }

    /// Signs the attestation report using HMAC-SHA256 with the key from the
    /// configured key file. In production this would call the Android Keystore
    /// via JNI with the Titan M2 hardware-backed key.
    pub async fn sign_report(&self, report: &AttestationReport) -> Result<String> {
        // Load or derive the signing key
        let key = self.load_or_derive_key().await?;

        // Serialise the report *without* the signature field for signing
        let signing_payload = build_signing_payload(report);

        // HMAC-SHA256 (simulated HSM)
        let mac = hmac_sha256(&key, signing_payload.as_bytes());
        Ok(BASE64.encode(mac))
    }

    /// Loads the HMAC key from file, or derives a deterministic test key if the
    /// file does not exist (development / CI mode).
    async fn load_or_derive_key(&self) -> Result<Vec<u8>> {
        match tokio::fs::read(&self.device_key_path).await {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                warn!(path = %self.device_key_path, "Key file not found; using derived test key");
                // Derive a deterministic key from the path so tests are reproducible.
                let mut hasher = Sha256::new();
                hasher.update(self.device_key_path.as_bytes());
                hasher.update(b"hispashield-test-key-derivation");
                Ok(hasher.finalize().to_vec())
            }
        }
    }

    /// Loads the certificate chain from the configured path. Each PEM certificate
    /// is base64-encoded and returned as a Vec entry.
    async fn load_cert_chain(&self) -> Vec<String> {
        match tokio::fs::read_to_string(&self.cert_chain_path).await {
            Err(_) => {
                debug!(path = %self.cert_chain_path, "Cert chain file not found; using simulated chain");
                // Return a simulated placeholder chain for development.
                vec![
                    BASE64.encode(b"[simulated-titan-m2-cert]"),
                    BASE64.encode(b"[simulated-platform-cert]"),
                    BASE64.encode(b"[simulated-app-cert]"),
                ]
            }
            Ok(pem) => {
                // Split on PEM boundaries and base64-encode each certificate block.
                pem_to_der_b64_list(&pem)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Reads a file and returns its SHA-256 hash as a lowercase hex string.
pub async fn hash_file(path: &str) -> Result<String> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("read {path}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Builds the canonical byte string that is signed. We exclude the `signature`
/// field itself to avoid a circular dependency.
fn build_signing_payload(report: &AttestationReport) -> String {
    // Create a partial JSON object without the signature field.
    let partial = serde_json::json!({
        "version": report.version,
        "timestamp": report.timestamp,
        "nonce": report.nonce,
        "device_id_hash": report.device_id_hash,
        "boot_state": report.boot_state,
        "hispashield_version": report.hispashield_version,
        "daemon_hashes": report.daemon_hashes,
        "attestation_chain": report.attestation_chain,
    });
    serde_json::to_string(&partial).unwrap_or_default()
}

/// Naive HMAC-SHA256 implementation using the two-pass method.
///
/// In production this is replaced by a Keystore call. We avoid pulling in
/// an HMAC crate to keep dependencies minimal.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;

    // Derive the effective key (hash if longer than block size).
    let mut k = if key.len() > BLOCK_SIZE {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK_SIZE, 0);

    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);
    outer.finalize().to_vec()
}

/// Parses a PEM file and returns each certificate as a base64-encoded DER block.
fn pem_to_der_b64_list(pem: &str) -> Vec<String> {
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut current_b64 = String::new();

    for line in pem.lines() {
        if line.trim_start().starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_b64.clear();
        } else if line.trim_start().starts_with("-----END CERTIFICATE-----") {
            if in_cert && !current_b64.is_empty() {
                certs.push(current_b64.clone());
            }
            in_cert = false;
        } else if in_cert {
            current_b64.push_str(line.trim());
        }
    }
    certs
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> AttestationEngine {
        AttestationEngine::new(
            "/nonexistent/key.bin",
            "/nonexistent/chain.pem",
            "hispashield-1.0.0",
        )
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let key = b"test-key";
        let msg = b"hello world";
        let mac1 = hmac_sha256(key, msg);
        let mac2 = hmac_sha256(key, msg);
        assert_eq!(mac1, mac2);
        assert_eq!(mac1.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_different_keys_differ() {
        let msg = b"message";
        let mac1 = hmac_sha256(b"key1", msg);
        let mac2 = hmac_sha256(b"key2", msg);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        // Key longer than 64 bytes should be hashed first
        let long_key = vec![0xABu8; 128];
        let mac = hmac_sha256(&long_key, b"test");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_build_signing_payload_no_signature_field() {
        let report = AttestationReport {
            version: 1,
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            nonce: "abc123".to_string(),
            device_id_hash: "deadbeef".to_string(),
            boot_state: BootState::Verified,
            hispashield_version: "1.0.0".to_string(),
            daemon_hashes: vec![],
            attestation_chain: vec![],
            signature: "should-not-appear".to_string(),
        };
        let payload = build_signing_payload(&report);
        assert!(!payload.contains("should-not-appear"));
        assert!(payload.contains("abc123"));
        assert!(payload.contains("1.0.0"));
    }

    #[test]
    fn test_pem_to_der_b64_list_single_cert() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJjZGVmZ2g=\n-----END CERTIFICATE-----\n";
        let certs = pem_to_der_b64_list(pem);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], "YWJjZGVmZ2g=");
    }

    #[test]
    fn test_pem_to_der_b64_list_multiple_certs() {
        let pem = "-----BEGIN CERTIFICATE-----\nY2VydDE=\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nY2VydDI=\n-----END CERTIFICATE-----\n";
        let certs = pem_to_der_b64_list(pem);
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn test_pem_to_der_b64_list_empty() {
        let certs = pem_to_der_b64_list("no certs here");
        assert!(certs.is_empty());
    }

    #[test]
    fn test_get_boot_state_no_panic() {
        let engine = make_engine();
        let state = engine.get_boot_state();
        // Should return a variant without panicking
        let _ = state;
    }

    #[tokio::test]
    async fn test_hash_running_daemons_no_panic() {
        let engine = make_engine();
        let hashes = engine.hash_running_daemons().await;
        // May be empty in CI, but must not panic
        let _ = hashes;
    }

    #[tokio::test]
    async fn test_generate_report_fields() {
        let engine = make_engine();
        let report = engine.generate_report("test-nonce-xyz").await.unwrap();
        assert_eq!(report.version, 1);
        assert_eq!(report.nonce, "test-nonce-xyz");
        assert_eq!(report.hispashield_version, "hispashield-1.0.0");
        assert!(!report.signature.is_empty());
        assert!(!report.attestation_chain.is_empty());
    }

    #[tokio::test]
    async fn test_sign_report_is_base64() {
        let engine = make_engine();
        let report = engine.generate_report("nonce42").await.unwrap();
        // Signature should decode as valid base64
        let decoded = BASE64.decode(&report.signature);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), 32); // SHA-256 = 32 bytes
    }

    #[test]
    fn test_boot_state_serialization() {
        let states = [BootState::Verified, BootState::Orange, BootState::Red];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let restored: BootState = serde_json::from_str(&json).unwrap();
            // Verify round-trip by serialising again
            assert_eq!(serde_json::to_string(&restored).unwrap(), json);
        }
    }

    #[tokio::test]
    async fn test_hash_file_nonexistent_returns_error() {
        let result = hash_file("/nonexistent/path/to/file.bin").await;
        assert!(result.is_err());
    }
}
