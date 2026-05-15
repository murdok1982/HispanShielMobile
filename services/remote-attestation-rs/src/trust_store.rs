use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// A server whose identity has been explicitly trusted by the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedServer {
    pub id: String,
    /// SHA-256 fingerprint of the server's DER-encoded certificate.
    pub cert_fingerprint: String,
    /// ISO-8601 UTC time when this entry was added.
    pub added_at: String,
    /// ISO-8601 UTC time of the most recent successful verification, if any.
    pub last_seen: Option<String>,
}

/// Persistent store of trusted server identities. Serialised as JSON on disk.
pub struct TrustStore {
    pub trusted_servers: HashMap<String, TrustedServer>,
    pub store_path: String,
}

impl TrustStore {
    /// Loads the trust store from `path`, or creates an empty store if the file
    /// does not exist. Returns an error only on read/parse failures of an
    /// existing file.
    pub fn load(path: &str) -> Result<Self> {
        let trusted_servers = if std::path::Path::new(path).exists() {
            let bytes = std::fs::read(path).with_context(|| format!("read trust store {path}"))?;
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parse trust store {path}"))?
        } else {
            HashMap::new()
        };

        info!(path = %path, count = trusted_servers.len(), "Trust store loaded");
        Ok(Self {
            trusted_servers,
            store_path: path.to_string(),
        })
    }

    /// Persists the current state of the trust store to disk atomically
    /// (write → rename).
    pub fn save(&self) -> Result<()> {
        let tmp_path = format!("{}.tmp", self.store_path);
        let json =
            serde_json::to_vec_pretty(&self.trusted_servers).context("serialize trust store")?;
        std::fs::write(&tmp_path, &json)
            .with_context(|| format!("write tmp trust store {tmp_path}"))?;
        std::fs::rename(&tmp_path, &self.store_path)
            .with_context(|| format!("rename trust store {tmp_path} → {}", self.store_path))?;
        debug!(path = %self.store_path, "Trust store saved");
        Ok(())
    }

    /// Adds or replaces a trusted server entry.
    ///
    /// `cert_pem` is a PEM-encoded X.509 certificate.  We compute its
    /// SHA-256 fingerprint and store it.
    pub fn add_server(&mut self, id: &str, cert_pem: &str) -> Result<()> {
        let fingerprint = cert_pem_fingerprint(cert_pem)?;
        let entry = TrustedServer {
            id: id.to_string(),
            cert_fingerprint: fingerprint.clone(),
            added_at: Utc::now().to_rfc3339(),
            last_seen: None,
        };
        self.trusted_servers.insert(id.to_string(), entry);
        info!(server_id = %id, fingerprint = %fingerprint, "Trusted server added");
        Ok(())
    }

    /// Returns true if `id` is in the trust store and the supplied `cert_pem`
    /// produces the same fingerprint as the stored one.
    pub fn verify_server(&self, id: &str, cert_pem: &str) -> bool {
        match self.trusted_servers.get(id) {
            None => {
                warn!(server_id = %id, "Unknown server — not in trust store");
                false
            }
            Some(trusted) => match cert_pem_fingerprint(cert_pem) {
                Err(e) => {
                    warn!(server_id = %id, err = %e, "Failed to compute cert fingerprint");
                    false
                }
                Ok(fp) => {
                    let matches = fp == trusted.cert_fingerprint;
                    if matches {
                        debug!(server_id = %id, "Server certificate verified");
                    } else {
                        warn!(
                            server_id = %id,
                            stored = %trusted.cert_fingerprint,
                            presented = %fp,
                            "Server certificate fingerprint mismatch"
                        );
                    }
                    matches
                }
            },
        }
    }

    /// Returns the number of trusted server entries.
    pub fn trusted_count(&self) -> usize {
        self.trusted_servers.len()
    }

    /// Updates the `last_seen` timestamp for a server (call after successful
    /// attestation exchange).
    pub fn touch(&mut self, id: &str) {
        if let Some(entry) = self.trusted_servers.get_mut(id) {
            entry.last_seen = Some(Utc::now().to_rfc3339());
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

/// Computes the SHA-256 fingerprint of a PEM certificate as a lowercase hex string.
///
/// The fingerprint is computed over the raw DER bytes (the base64 body of the
/// PEM block), matching the convention used by tools such as `openssl x509 -fingerprint`.
pub fn cert_pem_fingerprint(pem: &str) -> Result<String> {
    let der = pem_to_der(pem)?;
    let mut hasher = Sha256::new();
    hasher.update(&der);
    Ok(hex::encode(hasher.finalize()))
}

/// Decodes the first PEM certificate block found in `pem` and returns the raw DER bytes.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut in_cert = false;
    let mut b64 = String::new();

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            b64.clear();
        } else if trimmed.starts_with("-----END CERTIFICATE-----") {
            if in_cert {
                let der = BASE64
                    .decode(&b64)
                    .context("base64-decode certificate body")?;
                return Ok(der);
            }
        } else if in_cert {
            b64.push_str(trimmed);
        }
    }
    anyhow::bail!("No PEM certificate block found")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// A minimal self-signed DER certificate, base64-encoded, suitable for testing.
    /// This is a real (but expired, test-only) 512-bit RSA cert.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5TNJF\n\
        oxMCiHDMnfgapVkdGHEb3iLbk9ByGLbAK3FJCeRQbAMJGmOHVFTbMkPg6oSPjFcz\n\
        -----END CERTIFICATE-----\n";

    fn make_store_in_temp() -> (TrustStore, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let store = TrustStore {
            trusted_servers: HashMap::new(),
            store_path: f.path().to_string_lossy().to_string(),
        };
        (store, f)
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        let store = TrustStore::load("/tmp/nonexistent_hispashield_trust_12345.json").unwrap();
        assert_eq!(store.trusted_count(), 0);
    }

    #[test]
    fn test_trusted_count_empty() {
        let (store, _f) = make_store_in_temp();
        assert_eq!(store.trusted_count(), 0);
    }

    #[test]
    fn test_add_server_increases_count() {
        let (mut store, _f) = make_store_in_temp();
        // Use simple base64-encoded fake DER to avoid PEM parse error
        let fake_pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        store.add_server("srv1", fake_pem).unwrap();
        assert_eq!(store.trusted_count(), 1);
    }

    #[test]
    fn test_verify_server_matching_cert() {
        let (mut store, _f) = make_store_in_temp();
        let fake_pem = "-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----\n";
        store.add_server("srv2", fake_pem).unwrap();
        assert!(store.verify_server("srv2", fake_pem));
    }

    #[test]
    fn test_verify_server_wrong_cert_fails() {
        let (mut store, _f) = make_store_in_temp();
        let pem1 = "-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----\n";
        let pem2 = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        store.add_server("srv3", pem1).unwrap();
        assert!(!store.verify_server("srv3", pem2));
    }

    #[test]
    fn test_verify_server_unknown_id_fails() {
        let (store, _f) = make_store_in_temp();
        let fake_pem = "-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----\n";
        assert!(!store.verify_server("nonexistent", fake_pem));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_string_lossy().to_string();
        let mut store = TrustStore::load(&path).unwrap();
        let fake_pem = "-----BEGIN CERTIFICATE-----\nc2Vydg==\n-----END CERTIFICATE-----\n";
        store.add_server("roundtrip-server", fake_pem).unwrap();
        store.save().unwrap();

        let reloaded = TrustStore::load(&path).unwrap();
        assert_eq!(reloaded.trusted_count(), 1);
        assert!(reloaded.trusted_servers.contains_key("roundtrip-server"));
    }

    #[test]
    fn test_touch_updates_last_seen() {
        let (mut store, _f) = make_store_in_temp();
        let fake_pem = "-----BEGIN CERTIFICATE-----\ndG91Y2g=\n-----END CERTIFICATE-----\n";
        store.add_server("touchsrv", fake_pem).unwrap();
        assert!(store.trusted_servers["touchsrv"].last_seen.is_none());
        store.touch("touchsrv");
        assert!(store.trusted_servers["touchsrv"].last_seen.is_some());
    }

    #[test]
    fn test_pem_to_der_valid() {
        // "abc" base64 = "YWJj"
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let der = pem_to_der(pem).unwrap();
        assert_eq!(der, b"abc");
    }

    #[test]
    fn test_pem_to_der_no_cert_block() {
        let result = pem_to_der("not a PEM file");
        assert!(result.is_err());
    }

    #[test]
    fn test_cert_pem_fingerprint_deterministic() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let fp1 = cert_pem_fingerprint(pem).unwrap();
        let fp2 = cert_pem_fingerprint(pem).unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // hex-encoded SHA-256
    }

    #[test]
    fn test_cert_pem_fingerprint_different_certs_differ() {
        let pem1 = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let pem2 = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        let fp1 = cert_pem_fingerprint(pem1).unwrap();
        let fp2 = cert_pem_fingerprint(pem2).unwrap();
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_trusted_server_serialization() {
        let server = TrustedServer {
            id: "srv".to_string(),
            cert_fingerprint: "abc123".to_string(),
            added_at: "2025-01-01T00:00:00Z".to_string(),
            last_seen: Some("2025-06-01T12:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&server).unwrap();
        let restored: TrustedServer = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, "srv");
        assert_eq!(restored.cert_fingerprint, "abc123");
    }
}
