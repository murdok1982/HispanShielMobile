use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Invalid namespace in key '{0}' — must start with system., secure., global., or hispashield.")]
    InvalidNamespace(String),
    #[error("Key '{0}' is locked and cannot be overwritten")]
    KeyLocked(String),
    #[error("Key '{0}' not found")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

const VALID_NAMESPACES: &[&str] = &["system.", "secure.", "global.", "hispashield."];

fn validate_namespace(key: &str) -> Result<(), StoreError> {
    for ns in VALID_NAMESPACES {
        if key.starts_with(ns) && key.len() > ns.len() {
            return Ok(());
        }
    }
    Err(StoreError::InvalidNamespace(key.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StorageData {
    settings: HashMap<String, String>,
    /// Keys locked at boot (read-only)
    locked_keys: HashSet<String>,
}

pub struct SecureStore {
    data: StorageData,
    db_path: PathBuf,
}

impl SecureStore {
    /// Load store from `db_path`, creating it if absent.
    pub fn load(db_path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let db_path = db_path.into();
        let data = if db_path.exists() {
            let content = std::fs::read_to_string(&db_path)?;
            serde_json::from_str::<StorageData>(&content)?
        } else {
            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            StorageData::default()
        };
        info!(path = %db_path.display(), settings = data.settings.len(), "SecureStore loaded");
        Ok(Self { data, db_path })
    }

    pub fn get(&self, key: &str) -> Result<String, StoreError> {
        validate_namespace(key)?;
        self.data
            .settings
            .get(key)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(key.to_string()))
    }

    pub fn set(&mut self, key: &str, value: String) -> Result<(), StoreError> {
        validate_namespace(key)?;
        if self.data.locked_keys.contains(key) {
            warn!(key, "Attempted write to locked key");
            return Err(StoreError::KeyLocked(key.to_string()));
        }
        debug!(key, value = %value, "Setting key");
        self.data.settings.insert(key.to_string(), value);
        self.flush()
    }

    pub fn delete(&mut self, key: &str) -> Result<(), StoreError> {
        validate_namespace(key)?;
        if self.data.locked_keys.contains(key) {
            return Err(StoreError::KeyLocked(key.to_string()));
        }
        if self.data.settings.remove(key).is_some() {
            debug!(key, "Deleted key");
            self.flush()?;
        }
        Ok(())
    }

    /// Lock a key so it cannot be modified or deleted after boot.
    pub fn lock_key(&mut self, key: &str) -> Result<(), StoreError> {
        validate_namespace(key)?;
        self.data.locked_keys.insert(key.to_string());
        info!(key, "Key locked (read-only)");
        self.flush()
    }

    /// Atomically persist current state to disk.
    fn flush(&self) -> Result<(), StoreError> {
        let json = serde_json::to_string_pretty(&self.data)?;
        let tmp_path = self.db_path.with_extension("tmp");
        std::fs::write(&tmp_path, json.as_bytes())?;
        // Atomic rename
        std::fs::rename(&tmp_path, &self.db_path)?;
        debug!(path = %self.db_path.display(), "Settings flushed atomically");
        Ok(())
    }

    pub fn key_count(&self) -> usize {
        self.data.settings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_store() -> SecureStore {
        let mut path = env::temp_dir();
        path.push(format!("hispashield_test_{}.json", std::process::id()));
        SecureStore::load(path).unwrap()
    }

    #[test]
    fn test_set_get() {
        let mut store = tmp_store();
        store.set("system.foo", "bar".into()).unwrap();
        assert_eq!(store.get("system.foo").unwrap(), "bar");
    }

    #[test]
    fn test_invalid_namespace() {
        let mut store = tmp_store();
        assert!(matches!(
            store.set("unknown.foo", "v".into()),
            Err(StoreError::InvalidNamespace(_))
        ));
    }

    #[test]
    fn test_locked_key() {
        let mut store = tmp_store();
        store.set("secure.boot_verified", "true".into()).unwrap();
        store.lock_key("secure.boot_verified").unwrap();
        assert!(matches!(
            store.set("secure.boot_verified", "false".into()),
            Err(StoreError::KeyLocked(_))
        ));
        // Still readable
        assert_eq!(store.get("secure.boot_verified").unwrap(), "true");
    }

    #[test]
    fn test_delete() {
        let mut store = tmp_store();
        store.set("global.x", "y".into()).unwrap();
        store.delete("global.x").unwrap();
        assert!(matches!(store.get("global.x"), Err(StoreError::NotFound(_))));
    }
}
