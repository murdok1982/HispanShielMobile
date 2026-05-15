use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{fs, io::AsyncReadExt};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A known-good firmware file entry loaded from the hash database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareHash {
    /// Absolute path to the firmware blob on device storage.
    pub path: String,
    /// Expected SHA-256 digest in lowercase hexadecimal.
    pub expected_sha256: String,
    /// Human-readable description, e.g. "Qualcomm MDM9x55 baseband image".
    pub description: String,
}

/// Outcome of verifying a single firmware blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// File exists and its hash matches the known-good value.
    Ok,
    /// File exists but its hash differs from the known-good value.
    Tampered,
    /// File does not exist on the filesystem.
    Missing,
    /// The file has no known-good hash entry (unexpected firmware blob).
    Unknown,
}

/// Result of a single integrity check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Path that was checked.
    pub path: String,
    /// Outcome of the check.
    pub status: IntegrityStatus,
    /// Actual SHA-256 hex digest if the file was readable, otherwise `None`.
    pub actual_hash: Option<String>,
    /// Description carried over from the `FirmwareHash` entry.
    pub description: String,
}

// ---------------------------------------------------------------------------
// FirmwareGuard
// ---------------------------------------------------------------------------

/// Holds the set of known-good hashes and performs integrity verification.
pub struct FirmwareGuard {
    known_hashes: Vec<FirmwareHash>,
}

impl FirmwareGuard {
    /// Load the known-good hash database from a JSON file.
    ///
    /// Expected format:
    /// ```json
    /// [
    ///   { "path": "/vendor/firmware/modem.b00",
    ///     "expected_sha256": "abc…",
    ///     "description": "MDM baseband image" }
    /// ]
    /// ```
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading firmware hash database from {path}"))?;
        let known_hashes: Vec<FirmwareHash> =
            serde_json::from_str(&raw).with_context(|| "parsing firmware hash database JSON")?;
        info!("loaded {} known firmware hash entries", known_hashes.len());
        Ok(Self { known_hashes })
    }

    /// Construct directly from a pre-loaded list (useful for tests).
    pub fn from_known_hashes(known_hashes: Vec<FirmwareHash>) -> Self {
        Self { known_hashes }
    }

    /// Return references to all known hash entries.
    pub fn known_hashes(&self) -> &[FirmwareHash] {
        &self.known_hashes
    }

    /// Verify every known firmware blob.  Unknown blobs discovered via
    /// filesystem glob are NOT reported here; use `scan_directory` for that.
    pub async fn verify_all(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();
        for entry in &self.known_hashes {
            let result = self.verify_one(entry).await;
            results.push(result);
        }
        results
    }

    /// Verify a single firmware entry against its expected hash.
    async fn verify_one(&self, entry: &FirmwareHash) -> CheckResult {
        match compute_sha256_of_file(&entry.path).await {
            Err(e) if is_not_found(&e) => {
                warn!("firmware blob missing: {}", entry.path);
                CheckResult {
                    path: entry.path.clone(),
                    status: IntegrityStatus::Missing,
                    actual_hash: None,
                    description: entry.description.clone(),
                }
            }
            Err(e) => {
                warn!("error reading {}: {e}", entry.path);
                CheckResult {
                    path: entry.path.clone(),
                    status: IntegrityStatus::Unknown,
                    actual_hash: None,
                    description: entry.description.clone(),
                }
            }
            Ok(actual_hex) => {
                let ok = constant_time_eq(actual_hex.as_bytes(), entry.expected_sha256.as_bytes());
                if !ok {
                    warn!(
                        "firmware TAMPERED: {} expected={} actual={}",
                        entry.path, entry.expected_sha256, actual_hex
                    );
                }
                CheckResult {
                    path: entry.path.clone(),
                    status: if ok {
                        IntegrityStatus::Ok
                    } else {
                        IntegrityStatus::Tampered
                    },
                    actual_hash: Some(actual_hex),
                    description: entry.description.clone(),
                }
            }
        }
    }

    /// Compute the current SHA-256 of a firmware file and return the hex
    /// digest along with a description from the known-hash database (if any).
    ///
    /// Used to build the initial hash database on a trusted device.
    pub async fn compute_hash_for_path(path: &str) -> anyhow::Result<String> {
        compute_sha256_of_file(path).await
    }

    /// Summarise all check results into a single overall status string.
    pub fn overall_status(results: &[CheckResult]) -> &'static str {
        if results.iter().any(|r| r.status == IntegrityStatus::Tampered) {
            "tampered"
        } else if results.iter().any(|r| r.status == IntegrityStatus::Missing) {
            "unknown"
        } else if results.is_empty() {
            "unknown"
        } else {
            "ok"
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a file and return its SHA-256 digest as a lowercase hex string.
pub async fn compute_sha256_of_file(path: &str) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)
        .await
        .with_context(|| format!("opening {path}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .with_context(|| format!("reading {path}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .map(|io| io.kind() == std::io::ErrorKind::NotFound)
        .unwrap_or(false)
}

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
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    #[tokio::test]
    async fn test_verify_ok() {
        let data = b"modem firmware payload";
        let f = write_temp(data);
        let path = f.path().to_str().unwrap().to_string();
        let guard = FirmwareGuard::from_known_hashes(vec![FirmwareHash {
            path: path.clone(),
            expected_sha256: sha256_hex(data),
            description: "test blob".to_string(),
        }]);
        let results = guard.verify_all().await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, IntegrityStatus::Ok);
    }

    #[tokio::test]
    async fn test_verify_tampered() {
        let data = b"original firmware";
        let f = write_temp(data);
        let path = f.path().to_str().unwrap().to_string();
        let guard = FirmwareGuard::from_known_hashes(vec![FirmwareHash {
            path: path.clone(),
            expected_sha256: sha256_hex(b"different firmware"),
            description: "test blob".to_string(),
        }]);
        let results = guard.verify_all().await;
        assert_eq!(results[0].status, IntegrityStatus::Tampered);
    }

    #[tokio::test]
    async fn test_verify_missing() {
        let guard = FirmwareGuard::from_known_hashes(vec![FirmwareHash {
            path: "/nonexistent/path/modem.b00".to_string(),
            expected_sha256: sha256_hex(b"x"),
            description: "ghost blob".to_string(),
        }]);
        let results = guard.verify_all().await;
        assert_eq!(results[0].status, IntegrityStatus::Missing);
    }

    #[test]
    fn test_overall_status_ok() {
        let results = vec![CheckResult {
            path: "/f".to_string(),
            status: IntegrityStatus::Ok,
            actual_hash: Some("ab".to_string()),
            description: String::new(),
        }];
        assert_eq!(FirmwareGuard::overall_status(&results), "ok");
    }

    #[test]
    fn test_overall_status_tampered() {
        let results = vec![CheckResult {
            path: "/f".to_string(),
            status: IntegrityStatus::Tampered,
            actual_hash: Some("ab".to_string()),
            description: String::new(),
        }];
        assert_eq!(FirmwareGuard::overall_status(&results), "tampered");
    }

    #[test]
    fn test_overall_status_empty_is_unknown() {
        assert_eq!(FirmwareGuard::overall_status(&[]), "unknown");
    }

    #[tokio::test]
    async fn test_compute_hash_for_path() {
        let data = b"test data";
        let f = write_temp(data);
        let path = f.path().to_str().unwrap();
        let hash = FirmwareGuard::compute_hash_for_path(path).await.unwrap();
        assert_eq!(hash, sha256_hex(data));
    }
}
