//! Persistent, encrypted PQC keystore.
//!
//! Each key pair is serialised as a JSON file in `store_dir`. The secret key
//! bytes are XOR-encrypted with a master key (simulating AEAD / key-wrapping).
//! In production replace the XOR-wrap with AES-256-GCM or ChaCha20-Poly1305.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::algorithms::{Algorithm, PqcAlgorithms};

// ─── Persistent record ───────────────────────────────────────────────────────

/// Serialised representation stored on disk as `<store_dir>/<key_id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreEntry {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_b64: String,
    /// XOR-encrypted secret key, base64-encoded.
    pub encrypted_secret_b64: String,
    pub created_at: String,
}

/// Lightweight summary returned by `list_keys()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySummary {
    pub key_id: String,
    pub algorithm: String,
    pub created_at: String,
}

// ─── Master-key derivation ───────────────────────────────────────────────────

/// Derive a 32-byte master key from a hardware-token identifier (simulated).
///
/// In production this would call into an Android Keystore / TEE / StrongBox
/// operation instead of reading a file.
pub fn derive_master_key(store_dir: &str) -> Result<Zeroizing<Vec<u8>>> {
    let kek_path = PathBuf::from(store_dir).join(".kek");

    if kek_path.exists() {
        let raw = std::fs::read(&kek_path)
            .with_context(|| format!("Reading KEK from {:?}", kek_path))?;
        if raw.len() < 32 {
            bail!("KEK file too short");
        }
        return Ok(Zeroizing::new(raw[..32].to_vec()));
    }

    // First run: generate a random KEK and persist it.
    let mut kek = Zeroizing::new(vec![0u8; 32]);
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut kek);

    std::fs::create_dir_all(store_dir)
        .with_context(|| format!("Creating store dir: {store_dir}"))?;
    std::fs::write(&kek_path, &*kek)
        .with_context(|| format!("Writing KEK to {:?}", kek_path))?;

    info!("Generated new master KEK at {:?}", kek_path);
    Ok(kek)
}

// ─── Encryption helpers ───────────────────────────────────────────────────────

/// Expand `key` (32 bytes) to `n` bytes via SHA-256 counter-mode (KDF).
fn expand_key(key: &[u8], n: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    let mut ctr: u64 = 0;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(key);
        h.update(ctr.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        ctr += 1;
    }
    out.truncate(n);
    Zeroizing::new(out)
}

/// XOR-encrypt / decrypt `data` with `master_key` (key-stream generated via KDF).
fn xor_encrypt(master_key: &Zeroizing<Vec<u8>>, data: &[u8]) -> Vec<u8> {
    let key_stream = expand_key(master_key, data.len());
    data.iter().zip(key_stream.iter()).map(|(d, k)| d ^ k).collect()
}

// ─── PqcKeystore ─────────────────────────────────────────────────────────────

pub struct PqcKeystore {
    entries: HashMap<String, KeystoreEntry>,
    master_key: Zeroizing<Vec<u8>>,
    store_dir: String,
}

impl PqcKeystore {
    /// Open (or create) the keystore at `store_dir` using `master_key`.
    pub fn open(store_dir: &str, master_key: Zeroizing<Vec<u8>>) -> Result<Self> {
        std::fs::create_dir_all(store_dir)
            .with_context(|| format!("Creating keystore dir: {store_dir}"))?;

        let mut entries = HashMap::new();

        // Load existing entries from disk
        let dir = std::fs::read_dir(store_dir)
            .with_context(|| format!("Reading keystore dir: {store_dir}"))?;

        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<KeystoreEntry>(&content) {
                    Ok(ke) => {
                        debug!(key_id = %ke.key_id, "Loaded keystore entry");
                        entries.insert(ke.key_id.clone(), ke);
                    }
                    Err(e) => warn!("Failed to parse {:?}: {e}", path),
                },
                Err(e) => warn!("Failed to read {:?}: {e}", path),
            }
        }

        info!(
            count = entries.len(),
            store_dir, "Keystore opened"
        );

        Ok(Self {
            entries,
            master_key,
            store_dir: store_dir.to_string(),
        })
    }

    // ── Key generation ────────────────────────────────────────────────────────

    /// Generate a key pair for `algorithm`, store it, and return the public key.
    pub fn generate_and_store(&mut self, key_id: &str, algorithm: &Algorithm) -> Result<Vec<u8>> {
        if self.entries.contains_key(key_id) {
            bail!("Key ID already exists: {key_id}");
        }

        let kp = match algorithm {
            Algorithm::MlKem768 => PqcAlgorithms::ml_kem_768_keygen(),
            Algorithm::MlDsa65 => PqcAlgorithms::ml_dsa_65_keygen(),
            Algorithm::HybridX25519MlKem768 => PqcAlgorithms::hybrid_x25519_ml_kem_keygen(),
        };

        let public_key = kp.public_key.clone();

        // Encrypt secret key before persisting
        let encrypted_sk = xor_encrypt(&self.master_key, &kp.secret_key);

        let entry = KeystoreEntry {
            key_id: key_id.to_string(),
            algorithm: algorithm.as_str().to_string(),
            public_key_b64: BASE64.encode(&public_key),
            encrypted_secret_b64: BASE64.encode(&encrypted_sk),
            created_at: chrono_now(),
        };

        self.persist_entry(&entry)?;
        self.entries.insert(key_id.to_string(), entry);

        info!(key_id, algorithm = algorithm.as_str(), "Key pair generated and stored");

        Ok(public_key)
    }

    // ── Public-key retrieval ──────────────────────────────────────────────────

    pub fn get_public_key(&self, key_id: &str) -> Option<Vec<u8>> {
        let entry = self.entries.get(key_id)?;
        BASE64.decode(&entry.public_key_b64).ok()
    }

    // ── Signing ───────────────────────────────────────────────────────────────

    pub fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .get(key_id)
            .with_context(|| format!("Key not found: {key_id}"))?;

        if entry.algorithm != "ML-DSA-65" {
            bail!(
                "Key {} has algorithm {}, expected ML-DSA-65",
                key_id,
                entry.algorithm
            );
        }

        let sk = self.decrypt_secret(entry)?;
        let sig = PqcAlgorithms::ml_dsa_65_sign(&sk, data);
        Ok(sig)
    }

    // ── Encapsulation ─────────────────────────────────────────────────────────

    /// Encapsulate against an arbitrary public key (not necessarily stored here).
    pub fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok(PqcAlgorithms::ml_kem_768_encapsulate(public_key))
    }

    // ── Decapsulation ─────────────────────────────────────────────────────────

    pub fn decapsulate(
        &self,
        key_id: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let entry = self
            .entries
            .get(key_id)
            .with_context(|| format!("Key not found: {key_id}"))?;

        if entry.algorithm != "ML-KEM-768" && entry.algorithm != "HYBRID-X25519-ML-KEM" {
            bail!(
                "Key {} has algorithm {}, not a KEM key",
                key_id,
                entry.algorithm
            );
        }

        let sk = self.decrypt_secret(entry)?;
        Ok(PqcAlgorithms::ml_kem_768_decapsulate(&sk, ciphertext))
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    /// Delete a key pair. Returns `true` if it existed.
    pub fn delete(&mut self, key_id: &str) -> bool {
        if self.entries.remove(key_id).is_none() {
            return false;
        }
        let path = self.entry_path(key_id);
        if let Err(e) = std::fs::remove_file(&path) {
            warn!(key_id, "Failed to remove key file {:?}: {e}", path);
        }
        info!(key_id, "Key deleted");
        true
    }

    // ── List ──────────────────────────────────────────────────────────────────

    pub fn list_keys(&self) -> Vec<KeySummary> {
        let mut list: Vec<KeySummary> = self
            .entries
            .values()
            .map(|e| KeySummary {
                key_id: e.key_id.clone(),
                algorithm: e.algorithm.clone(),
                created_at: e.created_at.clone(),
            })
            .collect();
        list.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        list
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn decrypt_secret(&self, entry: &KeystoreEntry) -> Result<Zeroizing<Vec<u8>>> {
        let enc = BASE64
            .decode(&entry.encrypted_secret_b64)
            .context("Decoding encrypted secret")?;
        let raw = xor_encrypt(&self.master_key, &enc); // XOR is its own inverse
        Ok(Zeroizing::new(raw))
    }

    fn entry_path(&self, key_id: &str) -> PathBuf {
        PathBuf::from(&self.store_dir).join(format!("{}.json", sanitise_key_id(key_id)))
    }

    fn persist_entry(&self, entry: &KeystoreEntry) -> Result<()> {
        let path = self.entry_path(&entry.key_id);
        let json = serde_json::to_string_pretty(entry).context("Serialising keystore entry")?;
        std::fs::write(&path, json)
            .with_context(|| format!("Writing key entry to {:?}", path))?;
        Ok(())
    }
}

// ─── Utility functions ────────────────────────────────────────────────────────

/// Sanitise a key ID for use as a filename.
fn sanitise_key_id(key_id: &str) -> String {
    key_id
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Current UTC timestamp as RFC-3339-like string (no external chrono dep).
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Format as ISO-8601 UTC (approximate — no chrono dependency)
    let s = secs;
    let mins = s / 60;
    let hours = mins / 60;
    let days_total = hours / 24;
    let sec_part = s % 60;
    let min_part = (mins) % 60;
    let hour_part = hours % 24;
    // Approximate date calculation
    let year = 1970 + days_total / 365;
    let day_of_year = days_total % 365;
    let month = day_of_year / 30 + 1;
    let day = day_of_year % 30 + 1;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour_part, min_part, sec_part
    )
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Monotonic counter so each test gets its own directory.
    static TEST_CTR: AtomicU64 = AtomicU64::new(0);

    /// Create a unique temporary directory for a test and return its path.
    /// The directory is placed under `std::env::temp_dir()` and cleaned up
    /// after the test using a RAII guard.
    struct TestDir {
        path: String,
    }

    impl TestDir {
        fn new() -> Self {
            let n = TEST_CTR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("pqc-keystore-test-{}-{}", std::process::id(), n))
                .to_str()
                .unwrap()
                .to_string();
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &str {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn make_keystore() -> (TestDir, PqcKeystore) {
        let dir = TestDir::new();
        let mk = Zeroizing::new(vec![0xABu8; 32]);
        let ks = PqcKeystore::open(dir.path(), mk).unwrap();
        (dir, ks)
    }

    #[test]
    fn generate_and_list() {
        let (_dir, mut ks) = make_keystore();
        ks.generate_and_store("test-kem", &Algorithm::MlKem768).unwrap();
        ks.generate_and_store("test-dsa", &Algorithm::MlDsa65).unwrap();
        let list = ks.list_keys();
        assert_eq!(list.len(), 2);
        let ids: Vec<_> = list.iter().map(|e| e.key_id.as_str()).collect();
        assert!(ids.contains(&"test-kem"));
        assert!(ids.contains(&"test-dsa"));
    }

    #[test]
    fn get_public_key() {
        let (_dir, mut ks) = make_keystore();
        let pk = ks.generate_and_store("my-key", &Algorithm::MlDsa65).unwrap();
        let retrieved = ks.get_public_key("my-key").unwrap();
        assert_eq!(pk, retrieved);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (_dir, mut ks) = make_keystore();
        ks.generate_and_store("sign-key", &Algorithm::MlDsa65).unwrap();
        let data = b"important payload";
        let sig = ks.sign("sign-key", data).unwrap();
        let pk = ks.get_public_key("sign-key").unwrap();
        assert!(crate::algorithms::PqcAlgorithms::ml_dsa_65_verify(&pk, data, &sig));
    }

    #[test]
    fn sign_with_wrong_algo_fails() {
        let (_dir, mut ks) = make_keystore();
        ks.generate_and_store("kem-key", &Algorithm::MlKem768).unwrap();
        assert!(ks.sign("kem-key", b"data").is_err());
    }

    #[test]
    fn duplicate_key_id_fails() {
        let (_dir, mut ks) = make_keystore();
        ks.generate_and_store("dup", &Algorithm::MlDsa65).unwrap();
        assert!(ks.generate_and_store("dup", &Algorithm::MlDsa65).is_err());
    }

    #[test]
    fn delete_key() {
        let (_dir, mut ks) = make_keystore();
        ks.generate_and_store("del-key", &Algorithm::MlKem768).unwrap();
        assert!(ks.delete("del-key"));
        assert!(!ks.delete("del-key")); // second delete returns false
        assert!(ks.get_public_key("del-key").is_none());
    }

    #[test]
    fn encapsulate_produces_correct_sizes() {
        let (_dir, mut ks) = make_keystore();
        let pk = ks.generate_and_store("kem2", &Algorithm::MlKem768).unwrap();
        let (ct, ss) = ks.encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), crate::algorithms::ML_KEM_768_CT_BYTES);
        assert_eq!(ss.len(), crate::algorithms::ML_KEM_768_SS_BYTES);
    }

    #[test]
    fn persistence_roundtrip() {
        let dir = TestDir::new();
        let mk = Zeroizing::new(vec![0xCDu8; 32]);

        let pk_original = {
            let mut ks = PqcKeystore::open(dir.path(), mk.clone()).unwrap();
            ks.generate_and_store("persist-key", &Algorithm::MlDsa65).unwrap()
        };

        // Re-open and check key is still there
        let ks2 = PqcKeystore::open(dir.path(), mk).unwrap();
        let pk_loaded = ks2.get_public_key("persist-key").unwrap();
        assert_eq!(pk_original, pk_loaded);
    }
}
